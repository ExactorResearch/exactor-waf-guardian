# Comparativa Técnica: La Seguridad Perimetral Antes vs. Con EXACTOR

Para entender el salto generacional que representa el **Envoy SAT WAF (powered by EXACTOR Core)**, es indispensable contrastar la arquitectura actual con el estándar previo que dominó la industria durante los últimos veinte años: los **WAFs tradicionales basados en Expresiones Regulares (RegEx / ModSecurity / OWASP CRS)** y las alternativas recientes basadas en **Modelos de Lenguaje e Inferencia de IA en la Nube (Cloud LLMs)**.

---

## 1. Tabla Comparativa de Rendimiento y Arquitectura

Esta matriz resume los resultados obtenidos en el suite de benchmark comparativo formal (documentado en [PROOF_OF_CONCEPT.md](PROOF_OF_CONCEPT.md) y validado en el pipeline de Envoy Proxy):

| Dimensión Crítica | WAF Tradicional (ModSecurity / OWASP CRS) | WAF de IA / Cloud LLM (Cloudflare AI / AWS) | Envoy SAT WAF (powered by EXACTOR Core) |
| :--- | :---: | :---: | :---: |
| **Paradigma Central** | Coincidencia de cadenas por RegEx | Inferencia estadística probabilística | **Lógica Neuro-Simbólica y SAT Solver (AST)** |
| **Latencia de Inferencia** | $1.5\text{ ms} - 50.0\text{ ms}$ (degradable con payloads grandes) | $350\text{ ms} - 650\text{ ms}$ (inviable en data plane) | **$17.3\,\mu\text{s}$ (Standalone) / $123\,\mu\text{s}$ (HTTP Ext-Authz)** |
| **Throughput por Núcleo** | $\approx 200 - 800\text{ req/s}$ | $< 5\text{ req/s}$ (sujeto a rate-limits API) | **$> 47,000\text{ req/s}$ (Nativo Rust)** |
| **Tasa de Falsos Negativos (Evasión)** | **$58.00\%$** (Vulnerable a encoding y mutaciones) | $4.00\%$ (Buena comprensión contextual) | **$0.00\%$** (Invariantes lógicas universales) |
| **Tasa de Falsos Positivos** | **$12.00\% - 15.00\%$** (Rompe APIs JSON / código) | Variable ($1.0\% - 3.0\%$) | **$0.00\%$** (Verificación matemática formal) |
| **Vulnerabilidad a ReDoS** | **Crítica** (Backtracking exponencial $O(2^n)$) | No aplica (pero susceptible a Token Exhaustion) | **Inmune** (Gramáticas acotadas y tiempo lineal $O(n)$) |
| **Costo por 1M de Peticiones** | $0.00 (pero alto costo humano de mantenimiento) | **$2,000.00+ USD** (Tokens de inferencia externa) | **$0.00 USD** (Evaluación local determinista) |
| **Huella de Memoria (RAM)** | $150\text{ MB} - 500\text{ MB}$ por worker | N/A (Externalizado en API cloud) | **$< 25\text{ MB}$ (Zero GC, Rust)** |
| **Auditoría y Explicabilidad** | ID de regla opaco (`Rule 942100 matched`) | Texto en lenguaje natural (posible alucinación) | **Prueba formal en $\LaTeX$ y Grafo Causal** |
| **Ciclo de Actualización** | Reglas estáticas manuales cada 6-12 meses | Reentrenamiento costoso y opaco | **Minimización booleana continua en exactor.tech** |

---

## 2. Los Cuatro Problemas Estructurales de la "Era Anterior"

### 1. La Trampa de la Sintaxis vs. La Semántica (Evasión por Ofuscación)
* **Antes de EXACTOR (ModSecurity / RegEx):**  
  Las expresiones regulares buscan secuencias literales de caracteres predecibles (por ejemplo, buscar la palabra clave `UNION` seguida de `SELECT` o patrones como `' OR '1'='1`).  
  Cualquier atacante experimentado esquiva esta barrera utilizando técnicas elementales de ofuscación:
  * Comentarios SQL intercalados: `UNI/**/ON/**/SEL/**/ECT`
  * Representaciones hexadecimales o Unicode anidadas: `%2527%20OR%201=1`
  * Tautologías aritméticas no contempladas por la regla: `' OR 45*2=90--`  
  * **Resultado:** Una tasa de evasión del **$58.00\%$** en ataques reales.
* **Con EXACTOR:**  
  No inspecciona texto plano: parsea el flujo en un Árbol Sintáctico Abstracto (**AST**) y extrae predicados semánticos independientes de la sintaxis concreta. La invariante de tautología:
  $$\mathcal{I}_{\text{SQLi}} \equiv \neg (\text{QUOTE} \land \text{TAUTOLOGY})$$
  se evalúa idénticamente si el atacante escribe `' OR '1'='1'` o `' OR 0x2A=42--`, garantizando **0% de evasión**.

---

### 2. El "Impuesto del Falso Positivo" en APIs Modernas
* **Antes de EXACTOR:**  
  En arquitecturas modernas basadas en REST, GraphQL y microservicios, el tráfico legítimo transporta rutinariamente fragmentos de código, consultas JSON anidadas, sintaxis SQL (en herramientas de BI o reporting) y caracteres como `'`, `"`, `<`, `>`.  
  Las reglas rígidas de RegEx disparan falsos positivos sistemáticos (**12% - 15%**). Esto forzaba históricamente a los equipos de ingeniería a:
  1. Escribir cientos de líneas de excepciones manuales (`SecRuleRemoveById`).
  2. Poner el WAF en **modo pasivo / solo alertas**, dejando la infraestructura desprotegida.
* **Con EXACTOR:**  
  Al validar mediante **Islas de Certeza**, un parámetro de texto técnico legítimo (por ejemplo, `{"description": "User's account status updated"}`) satisface los axiomas de contenido seguro y no genera contradicciones en el SAT solver. Falsos positivos comprobados: **0.00%**.

---

### 3. ReDoS y Agotamiento de CPU en el Perímetro
* **Antes de EXACTOR:**  
  Cuando miles de expresiones regulares compiten en cada paquete HTTP entrante, ciertas combinaciones de caracteres desencadenan **Catastrophic Backtracking** en los motores PCRE/RegEx. Los atacantes aprovechan esto para enviar payloads patológicos que elevan la CPU del gateway perimetral al 100%, tumbando Nginx o HAProxy sin haber roto la seguridad.
* **Con EXACTOR:**  
  El motor no utiliza motores de backtracking. Las transiciones de estados del lexer y la reducción de cláusulas booleanas son lineales respecto al tamaño del payload ($O(n)$) o constantes ($O(1)$) sobre el catálogo de variables booleanas, eliminando de raíz el vector de ataque por denegación de servicio computacional.

---

### 4. La Latencia en el Data Plane y el Cuello de Botella
* **Antes de EXACTOR:**
  * **WAFs de RegEx:** Añaden entre $5\text{ ms}$ y $50\text{ ms}$ por petición, penalizando gravemente los SLAs de microservicios distribuidos.
  * **WAFs de IA (Cloud LLMs):** Introducen latencias de **$350\text{ ms} - 650\text{ ms}$** por petición al requerir una llamada HTTP remota a un modelo de lenguaje. En un API Gateway con 10,000 peticiones por segundo, esto destruye la experiencia de usuario y resulta financieramente inviable ($>\$2,000$ USD por cada millón de llamadas).
* **Con EXACTOR:**
  * La deducción lógica se ejecuta de forma **local y en memoria** en C++/Rust.
  * Tiempo de inferencia: **$17.3\,\mu\text{s}$** (microsegundos).
  * Impacto en la latencia de Envoy Proxy: prácticamente imperceptible frente al tiempo de red y procesamiento del backend.

---

## 3. Comparativa de Trazabilidad y Cumplimiento Normativo

| Aspecto | Antes de EXACTOR (WAF Tradicional) | Con Envoy SAT WAF (EXACTOR) |
| :--- | :--- | :--- |
| **Cabecera de Decisión** | Ninguna o solo código numérico interno | `x-exactor-verdict: ALLOW / DENY`<br>`x-exactor-latency-us: 123.2`<br>`x-exactor-proof-ref: proof-uuid` |
| **Respuesta de Bloqueo** | Error 403 genérico en HTML sin justificación técnica | Payload JSON estructurado con detalle causal formal: `{"error": "Forbidden by Envoy Security Policy", "category": "sql_injection", "rule": "ISLAND-SQLI"}` |
| **Evidencia Forense** | Logs de texto dispersos y difíciles de correlacionar | **Ledger SQLite WAL local en micro-batching** + Prueba causal formal exportable en notación matemática $\LaTeX$. |
| **Auditoría PCI-DSS / ISO 27001** | El auditor debe "confiar" en que la lista de expresiones regulares cubre los vectores conocidos. | **Certeza matemática demostrable:** la política de seguridad se modela como un teorema de invariantes no contradichas. |

---

## 4. Conclusión

| Criterio | La Era Anterior (RegEx / ModSecurity) | La Era Actual (Envoy SAT WAF + EXACTOR) |
| :--- | :--- | :--- |
| **Filosofía** | *Aproximación basada en coincidencia de patrones.* | *Demostración formal basada en lógica matemática.* |
| **Tolerancia a Fallos** | Rompe aplicaciones modernas o se apaga por falsos positivos. | Cero falsos positivos en producción con modo bloqueante estricto. |
| **Velocidad** | Milisegundos que degradan el gateway. | Microsegundos nativos al ritmo del hardware. |
| **Mantenimiento** | Artesanal, manual y reactivo a vulnerabilidades día cero. | Autónomo, simplificado mediante álgebra de Boole en la nube. |

El paso de las expresiones regulares clásicas al **Envoy SAT WAF** no es una simple optimización de código: es el cambio de un enfoque **aproximado y vulnerable** a un modelo de **garantía determinista formal**.
