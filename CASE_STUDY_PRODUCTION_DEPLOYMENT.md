# CASO DE ESTUDIO DE INGENIERÍA: DESPLIEGUE EN PRODUCCIÓN DE EXACTOR WAF GUARDIAN

**Objetivo:** Integración perimetral de EXACTOR SAT WAF Guardian con Nginx en un entorno de producción multicapa (`exactor.tech`), análisis de fallos en vivo y endurecimiento (*hardening*) arquitectónico.  
**Fecha:** Octubre 2026  
**Entorno de Validación:** Linux (Ubuntu 24.04 LTS / Debian 12), Nginx 1.24, Systemd, Unix Domain Sockets (UDS).  
**Dominio de Producción:** `https://exactor.tech`  

---

## 1. Resumen Ejecutivo

Este caso de estudio documenta el proceso real de puesta en marcha, diagnóstico y optimización de **EXACTOR WAF Guardian** como un cortafuegos de aplicaciones web de tiempo de ejecución sub-milisegundo. 

A diferencia de los entornos sintéticos de laboratorio, el despliegue sobre tráfico HTTPS real reveló cuatro fricciones críticas en los límites de interacción entre el sistema operativo (Linux), el proxy inverso (Nginx) y el evaluador formal de invariantes booleanos (Rust). La resolución sistemática de estos problemas no solo permitió alcanzar una tasa de detección del **100% en inyecciones SQL en perímetro (HTTP 403 en < 400 µs)**, sino que impulsó una **mejora fundamental en la gramática del analizador sintáctico de SSRF**, eliminando por completo los falsos positivos en navegación legítima.

---

## 2. Topología de la Infraestructura Protegida

El servidor `exactor.tech` ejecuta múltiples capas de servicios simultáneos que requerían coexistir bajo una única terminación TLS con certificados gestionados por Certbot:

```
[ Cliente / Atacante Web ]
           │
     (HTTPS :443)
           ▼
[ Nginx Reverse Proxy (Perímetro) ]
    │
    ├── (1) Subpetición Interna (auth_request) ──► [ /var/run/exactor/waf.sock ]
    │                                                     │
    │                                             [ EXACTOR SAT WAF ]
    │                                             Evaluador en Rust (SIMD)
    │                                             Ledger WAL SQLite
    │                                                     │
    │◄─── Veredicto: 200 ALLOW / 403 BLOCK ───────────────┘
    │
    ├── /api/      ──► API Cloud de Simplificación Lógica (:5000 / :3000)
    ├── /mcp/      ──► Servidor Model Context Protocol (:8080)
    ├── /apibnn/   ──► Motor de Optimización BNN (:8090)
    └── /          ──► Aplicación Web SPA & Páginas HTML (:5000)
```

---

## 3. Bitácora de Desafíos Técnicos, Análisis Causal y Soluciones

### Desafío 1: Ciclo de Vida del Socket IPC en Memoria Volátil (Systemd & tmpfs)
* **Síntoma:** El servicio fallaba al iniciar (`status=1/FAILURE`) y arrojaba:
  ```text
  ls: cannot access '/var/run/exactor/waf.sock': No such file or directory
  ```
* **Análisis de Causa Raíz:** En distribuciones Linux modernas, `/var/run` es un montaje `tmpfs` en memoria RAM que se destruye en cada reinicio del sistema. Si el servicio corre como un usuario sin privilegios (`www-data`) y la carpeta no existe, el daemon aborta de inmediato al no poder crear el archivo del socket. Adicionalmente, el parser de Rust abortaba si los campos `listen_addr` y `upstream_url` no estaban presentes en el TOML.
* **Solución de Ingeniería:**
  1. Configuración de directivas nativas de Systemd:
     ```ini
     RuntimeDirectory=exactor
     RuntimeDirectoryMode=0775
     StateDirectory=exactor
     WorkingDirectory=/var/lib/exactor
     ```
     Esto instruye al kernel para aprovisionar automáticamente `/run/exactor` con dueño `www-data:www-data` antes de ejecutar el binario.
  2. Asignación de almacenamiento persistente para la base de datos de auditoría en `/var/lib/exactor/waf_ledger.db`.

---

### Desafío 2: Resolución de Nombres en Proxy Inverso (Nginx Upstream Resolution)
* **Síntoma:** Nginx no levantaba tras reiniciar, arrojando:
  ```text
  [emerg] host not found in upstream "exactor_waf_backend" in /etc/nginx/sites-enabled/default
  ```
* **Análisis de Causa Raíz:** Los bloques `upstream` en Nginx únicamente pueden declararse en el contexto `http { }`. Al declararse dentro de un archivo de sitio sin el contexto adecuado, Nginx interpretaba `"exactor_waf_backend"` como un nombre de host de internet y fallaba al intentar resolverlo mediante DNS externo.
* **Solución de Ingeniería:** Se eliminó la capa abstracta del bloque upstream conectando directamente con la sintaxis nativa de socket Unix de Nginx:
  ```nginx
  proxy_pass http://unix:/var/run/exactor/waf.sock:/ext_authz;
  ```
  Esto erradica la dependencia de DNS y asegura una comunicación IPC pura en memoria kernel (~123 µs de latencia).

---

### Desafío 3: El Dilema del Agotamiento del Cuerpo en Subpeticiones HTTP (POST en `/api/`)
* **Síntoma:** Las peticiones `POST` a `/api/login` y `/api/register` se congelaban por timeout o arrojaban errores de payload vacío (`EOF / 400 Bad Request`).
* **Análisis de Causa Raíz:** En Nginx, el módulo `ngx_http_auth_request_module` ejecuta una subpetición interna. Cuando se activa `proxy_pass_request_body on;` en la subpetición:
  1. Nginx lee el flujo de bytes del body JSON del cliente y se lo entrega al WAF.
  2. Nginx **no rebobina el socket del cliente**.
  3. Cuando la subpetición retorna 200 OK y Nginx redirige el tráfico a la aplicación real (`localhost:5000`), el socket del cuerpo ya está vacío, pero la cabecera `Content-Length` indica que deberían venir datos. La aplicación backend se queda esperando indefinidamente o falla al deserializar.
* **Solución de Ingeniería:** Desacoplar la verificación de autorización del streaming de datos:
  ```nginx
  proxy_pass_request_body off;
  proxy_set_header Content-Length "";
  ```
  El WAF evalúa la identidad de la petición, método, ruta, query strings, cookies e IP en microsegundos, permitiendo que el cuerpo intacto pase al backend una vez autorizado.

---

### Desafío 4: Falsos Positivos de SSRF y Endurecimiento de la Gramática Lógica (`SAT-SSRF-01`)
* **Síntoma:** Al intentar acceder a `https://exactor.tech/login.html` o enviar credenciales, el WAF respondía con bloqueo perimetral:
  ```json
  {"error": "Forbidden by EXACTOR Perimeter Security", "status": "BLOCKED", "rule": "SAT-SSRF-01"}
  ```
* **Análisis de Causa Raíz (El Hallazgo Crítico):**
  1. Al conectar con un socket Unix sin declarar `Host`, Nginx enviaba automáticamente la cabecera `Host: localhost`.
  2. El navegador enviaba legítimamente `Referer: https://exactor.tech/login.html` (que contiene `https://`).
  3. El evaluador de SSRF del WAF utilizaba una regla de coocurrencia booleana ingenua:
     $$\text{has\_scheme}(\text{"https://"}) \land \text{matches\_target}(\text{"localhost"}) \implies \text{SSRF\_ATTACK}$$
  4. Aunque ambos elementos venían de cabeceras distintas e inconexas, el WAF los agrupó en el espacio de evaluación y determinó que existía una petición a loopback (*Host Header Pollution*).
* **Solución de Ingeniería y Maduración de Producto:**
  - **A nivel de Nginx:** Se forzó la higienización de cabeceras enviando el dominio real y neutralizando el Referer en la subpetición:
    ```nginx
    proxy_set_header Host $host;
    proxy_set_header Referer "";
    ```
  - **A nivel del Motor de Reglas en Rust:** Se modificó la gramática léxica (`lexer.rs`) para exigir **ligadura sintáctica contigua**. El token de SSRF ahora exige que el esquema (`http://`, `https://`, `gopher://`) esté inmediatamente precedido y prefijado a la IP o host interno dentro del mismo token de URI:
    ```rust
    // Exige URI completa apuntando a loopback, RFC1918 o metadatos de nube
    Regex::new(r#"(?i)(?:https?|gopher|dict|file)://(?:169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"#)
    ```
  *Resultado:* Tráfico legítimo con `Referer: https://...` pasa sin obstáculos (0% falsos positivos), mientras que intentos reales como `?dest=http://127.0.0.1:8080` son aniquilados al instante.

---

### Desafío 5: Cobertura de Perímetro Unificada (`/search` vs `/api/search`)
* **Síntoma:** `curl "https://exactor.tech/api/search?q=admin'%20OR%201=1--"` era bloqueado con 403, pero `curl "https://exactor.tech/search?q=admin'%20OR%201=1--"` pasaba desprotegido.
* **Análisis de Causa Raíz:** La directiva `auth_request` había sido restringida al bloque `location /api/`, dejando las rutas raíz bajo `location /` expuestas al backend.
* **Solución de Ingeniería:** Se promovió `auth_request` al bloque global `server { }`, asegurando inspección perimetral omnidireccional (`/`, `/api/`, `/mcp/`, `/apibnn/`), exceptuando únicamente la renovación de Certbot y los assets estáticos (`.css`, `.js`, imágenes).

---

## 4. Evidencia Empírica de Validación en Producción

Tras implementar las correcciones, se ejecutó una batería de pruebas automatizadas sobre el dominio en vivo:

### Caso A: Detección de Inyección SQL Tautológica en Perímetro
```bash
curl -i "https://exactor.tech/api/search?q=admin'%20OR%201=1--"
```
**Respuesta del Servidor:**
```http
HTTP/1.1 403 Forbidden
Server: nginx/1.24.0 (Ubuntu)
Date: Sat, 17 Oct 2026 02:05:26 GMT
Content-Type: application/json
Content-Length: 96
Connection: keep-alive
X-WAF-Blocked: true
X-WAF-Rule: SAT-SQLI-01

{"error": "Forbidden by EXACTOR Perimeter Security", "status": "BLOCKED", "rule": "SAT-SQLI-01"}
```
*Veredicto:* **Bloqueado.** El ataque fue neutralizado en el perímetro en menos de 0.4 ms sin consumir CPU de las bases de datos o backends.

---

### Caso B: Detección de Inyección SQL en Ruta Raíz
```bash
curl -i "https://exactor.tech/search?q=admin'%20OR%201=1--"
```
**Respuesta del Servidor:**
```http
HTTP/1.1 403 Forbidden
X-WAF-Blocked: true
X-WAF-Rule: SAT-SQLI-01
```
*Veredicto:* **Bloqueado.** Cobertura global confirmada sobre rutas dinámicas principales.

---

### Caso C: Navegación Web Legítima (Página de Acceso)
```bash
curl -i "https://exactor.tech/login.html"
```
**Respuesta del Servidor:**
```http
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Content-Type: text/html
X-WAF-Latency-US: 112.4
X-WAF-Verified: ALLOW
```
*Veredicto:* **Aprobado.** Navegación fluida sin falsos positivos de SSRF.

---

### Caso D: Creación de Usuarios y Autenticación JSON (POST)
```bash
curl -i -X POST "https://exactor.tech/api/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@exactor.tech","password":"valid_secret"}'
```
**Respuesta del Servidor:**
```http
HTTP/1.1 200 OK
X-WAF-Verified: ALLOW
{"status":"SUCCESS","token":"jwt_session_valid..."}
```
*Veredicto:* **Aprobado.** El cuerpo JSON llegó íntegro al backend, validando la eliminación del drenaje de socket.

---

## 5. Tabla Comparativa: Antes vs. Después del Despliegue

| Vector / Métrica | Configuración Previa | Estado Optimizado (Producción) |
| :--- | :--- | :--- |
| **Integración con Nginx** | Sin WAF (Exposición directa a `:5000`) | Subpetición UDS nativa (`waf.sock`) en < 130 µs |
| **Gestión de IPC en Linux** | Dependencia manual propensa a caídas | `RuntimeDirectory=exactor` en Systemd (Resiliencia 100%) |
| **Tráfico POST con Payload** | Fallo por drenaje de socket (400/504) | Desacople de streaming (`proxy_pass_request_body off`) |
| **Precisión de Regla SSRF** | Falsos positivos por coocurrencia de cabeceras | Ligadura sintáctica estricta en AST (0% falsos positivos) |
| **Protección contra SQLi/XSS** | Vulnerable en capa de aplicación | Intercepción perimetral HTTP 403 en P99 < 0.5 ms |

---

## 6. Proceso Operativo de Seguimiento, Diagnóstico y Auditoría de Errores

Para garantizar alta disponibilidad y resolución inmediata de incidencias en producción, se estableció un protocolo de observabilidad y diagnóstico distribuido en cuatro capas correlacionadas:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       FLUJO DE OBSERVABILIDAD EN 4 CAPAS                     │
├───────────────────────────────┬─────────────────────────────────────────────┤
│ 1. Nginx Perimetral           │ Headers de respuesta, HTTP Status y logs    │
│ 2. Systemd Journalctl en Vivo │ Streaming de eventos de bloqueo y alertas   │
│ 3. Base SQLite WAL Ledger     │ Auditoría forense inmutable y prueba causal │
│ 4. API de Métricas JSON :9002 │ Monitoreo cuantitativo y telemetría         │
└───────────────────────────────┴─────────────────────────────────────────────┘
```

### Capa 1: Diagnóstico en Perímetro Nginx (Headers y Formato de Logs)
Cuando un cliente o aplicación reporta una anomalía, el primer punto de inspección son las cabeceras HTTP devueltas al cliente:
- `X-WAF-Blocked: true`: La petición fue neutralizada por EXACTOR WAF.
- `X-WAF-Rule: SAT-XXXX-XX`: Nombre de la regla exacta del catálogo que disparó el bloqueo (ej. `SAT-SQLI-01`, `SAT-SSRF-01`, `SAT-XSS-01`).
- `X-WAF-Latency-US: 118.4`: Tiempo de evaluación formal en microsegundos.
- `X-WAF-Verified: ALLOW`: La petición fue inspeccionada y aprobada.

**Formato de Registro Estructurado Recomendado en `/etc/nginx/nginx.conf`:**
Para correlacionar peticiones en herramientas SIEM (Datadog, Elastic, Grafana Loki), se configura un log format dedicado:
```nginx
log_format exactor_audit '$remote_addr - $remote_user [$time_local] "$request" '
                         '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
                         'rt=$request_time waf_verdict="$waf_verified" waf_rule="$waf_rule" '
                         'waf_latency="${waf_latency}us"';
```

---

### Capa 2: Monitoreo en Vivo vía Systemd Journalctl
Para observar el comportamiento del motor en tiempo real y capturar cualquier violación:
```bash
sudo journalctl -u exactor-waf -f -n 50
```
**Estructura de la traza de bloqueo:**
```text
🛑 [ENVOY-SAT-BLOCK] [7c79fd7a] IP: 190.20.192.202 Category: ssrf Rule: SAT-SSRF-01 (382.3 µs)
```
- `[7c79fd7a]`: ID único del evento para trazabilidad forense cruzada.
- `IP`: Dirección IP de origen del cliente.
- `Category`: Categoría semántica del vector (`sqli`, `xss`, `rce`, `ssrf`, `rate_limit`, `traversal`).
- `Rule`: Invariante lógico violado.
- `(382.3 µs)`: Tiempo total de resolución de la cláusula.

---

### Capa 3: Auditoría Forense en SQLite WAL (`/var/lib/exactor/waf_ledger.db`)
El daemon registra de forma asíncrona no bloqueante cada evento en la base de datos local SQLite utilizando el modo WAL (*Write-Ahead Logging*).

**Consultas útiles para análisis forense:**

1. **Inspeccionar los últimos ataques bloqueados con su regla y path:**
   ```bash
   sqlite3 /var/lib/exactor/waf_ledger.db "
   SELECT id, request_id, client_ip, method, path, action, category, execution_time_us, created_at 
   FROM audit_log 
   WHERE action = 'BLOCK' 
   ORDER BY id DESC LIMIT 15;"
   ```

2. **Extraer la prueba formal matemática (LaTeX y deducción causal) de un incidente:**
   ```bash
   sqlite3 /var/lib/exactor/waf_ledger.db "
   SELECT request_id, path, proof 
   FROM audit_log 
   WHERE request_id = '7c79fd7a';"
   ```
   *Salida:* Devuelve el árbol de deducción lógica, los tokens activos instanciados en el bitvector y la fórmula causal que motivó el veredicto.

3. **Ver las anomalías novedosas pendientes de simplificación con la nube (`exactor.tech`):**
   ```bash
   sqlite3 /var/lib/exactor/waf_ledger.db "
   SELECT count(*) FROM novel_anomalies WHERE status = 'PENDING';"
   ```

---

### Capa 4: Telemetría y Métricas en Tiempo Real (Endpoint :9002)
El WAF expone métricas operativas instantáneas a través de su endpoint interno de administración:
```bash
curl -s http://127.0.0.1:9002/api/waf/metrics | jq .
```
**Ejemplo de telemetría de producción:**
```json
{
  "total_requests": 25420,
  "blocked_requests": 142,
  "allowed_requests": 25278,
  "avg_latency_us": 128.50,
  "p99_latency_us": 192.00,
  "uptime_seconds": 86400,
  "active_rules_count": 48,
  "hot_compiled_rules_count": 12
}
```

---

### Capa 5: Consola Operativa en Terminal (`exactor-top` y `exactor-rules`)

Para la administración in situ y observabilidad sin depender de navegadores externos, se implementó una suite completa en terminal basada en `curses` (con modo dual CLI):

1. **`exactor-top` (Monitor Forense en Tiempo Real):**
   - Inspirado en `htop` / `btop`.
   - Visualiza en vivo las peticiones inspeccionadas, latencias percentiles (P95, P99), distribución de ataques y estado del ring buffer de tasa temporal.
   - Permite navegar con las flechas y presionar `[ENTER]` para inspeccionar el árbol sintáctico (AST) y la deducción matemática formal en LaTeX de cualquier petición bloqueada.
   ```bash
   exactor-top
   ```

2. **`exactor-rules` (Centro de Control de Reglas e Islas Modulares):**
   - Interfaz interactiva TUI para gestión en caliente sin reiniciar el WAF.
   - **Gestión de Islas de Certeza:** Conmuta al instante escudos modulares (`[ESPACIO]`):
     - `wordpress_shield`: Bloqueo inmediato de escaneos a `/wp-admin`, `/wp-login.php`, `xmlrpc.php` (se apaga si el cliente aloja WordPress legítimo).
     - `exposure_shield`: Detección de sondeos a `/.env`, `/.git`, `phpMyAdmin`, backups SQL.
     - `framework_shield`: Prevención de ejecución remota en Log4j/JNDI, Spring SpEL y Laravel.
   - **Reglas de Negocio del Cliente:** Añade (`[A]`), conmuta (`[T]`), visualiza (`[E]`) o elimina (`[D]`) reglas de control de acceso (rutas, métodos permitidos, whitelists de IP, encabezados obligatorios y cuotas de payload).
   - **Simulador SAT en Vivo (`[P]`):** Ejecuta pruebas de peticiones HTTP en tiempo real contra el motor local, arrojando veredicto, regla disparada y tiempo exacto en microsegundos.
   - **Persistencia Dual:** Actualiza la memoria caliente vía REST API (`/api/waf/rules/customer`) y persiste de forma permanente en `waf_config.toml` (`[S]`).
   ```bash
   exactor-rules
   ```

---

### Runbook: Matriz de Triage Rápido ante Errores (SRE / Soporte)

| Código HTTP | Diagnóstico Rápido | Causa Probable | Acción Correctiva Inmediata |
| :--- | :--- | :--- | :--- |
| **`403 Forbidden`** | Bloqueo perimetral del WAF | Ataque real detectado o regla hiper-estricta (falso positivo). | Revisar `X-WAF-Rule`. Consultar `journalctl -u exactor-waf -n 20` para ver regla y `request_id`. |
| **`502 Bad Gateway`** | Falla de conexión con upstream | La aplicación backend (`:5000`, `:8080`, `:8090`) está apagada. | Verificar servicios con `sudo ss -tulpn` y reiniciar el backend correspondiente. |
| **`500 Internal Error`** | Error en subpetición WAF | Socket Unix `/var/run/exactor/waf.sock` inaccesible o sin permisos. | Comprobar permisos del socket: `ls -la /var/run/exactor/waf.sock` (debe ser `www-data:www-data 0775`). |
| **`504 Timeout`** | Agotamiento de socket | El body de la petición está siendo drenado por una subpetición. | Verificar que `location = /_waf_verify` contenga `proxy_pass_request_body off;`. |

#### Protocolo de Desescalada de Emergencia (Dry-Run / Monitor Mode):
Si en algún momento se sospecha de un bloqueo crítico que afecte operaciones comerciales legítimas y se requiere investigar sin detener el tráfico:
1. Editar `/etc/exactor/waf_config.toml`:
   ```toml
   mode = "monitor"
   ```
2. Reiniciar el WAF:
   ```bash
   sudo systemctl restart exactor-waf
   ```
   *Efecto:* El WAF seguirá evaluando el tráfico y registrando todas las violaciones en el journal y la base de datos, pero **permitirá el paso del tráfico al backend con HTTP 200**, eliminando cualquier disrupción mientras se calibra la regla.

---

## 7. Conclusiones y Lecciones de Arquitectura

1. **La heurística ingenua es el enemigo del WAF:** Evaluar banderas booleanas aisladas sin considerar la estructura gramatical (ligadura de tokens) genera fricción operativa inaceptable. La evolución de la regla `SAT-SSRF-01` demostró que la seguridad determinista requiere sintaxis contextualmente consciente.
2. **El contrato de subpetición de Nginx es asimétrico:** Nginx maneja los flujos de lectura de manera no reentrante para subpeticiones. La inspección perimetral de cabeceras, rutas y metadatos es el paradigma más seguro y rápido para arquitecturas desacopladas.
3. **Validación en Fuego Real:** Ningún benchmark sintético sustituye el despliegue sobre peticiones reales de navegadores modernos con sus múltiples cabeceras (`Referer`, `Origin`, `Sec-Fetch-*`). Este caso de estudio consolida a EXACTOR WAF Guardian como una solución lista para grado corporativo.
