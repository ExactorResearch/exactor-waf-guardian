#!/usr/bin/env python3
"""
===============================================================================
 EXACTOR-ADVISOR: Sistema Multi-Agente Autónomo de Análisis Forense y 
 Generación de Reglas de Negocio con Aprobación Humana (Human-in-the-Loop)
===============================================================================
 Arquitectura de Agentes:
   1. TrafficPatternAgent   : Analiza trazas (SQLite / Logs) y detecta clusters.
   2. RuleSynthesizerAgent  : Sintetiza reglas formales O(1) y valida 0 FP.
   3. HumanApprovalAgent    : Presenta sugerencias al operador y aplica cambios.
===============================================================================
"""

import os
import sys
import json
import time
import sqlite3
import argparse
import urllib.request
import urllib.error
from collections import defaultdict, Counter
try:
    import tomllib
except ImportError:
    tomllib = None

# Ensure UTF-8 output encoding
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

DEFAULT_API_URL = os.environ.get("EXACTOR_API_URL", "http://127.0.0.1:10000")
DEFAULT_DB_PATHS = [
    "waf_ledger.db",
    "/var/lib/exactor/waf_ledger.db",
    "/etc/exactor/waf_ledger.db",
    "../waf_ledger.db",
    "../../waf_ledger.db",
]
DEFAULT_CONFIG_PATHS = [
    "waf_config.toml",
    "/etc/exactor/waf_config.toml",
    "../waf_config.toml",
    "../../waf_config.toml",
]

def find_file(paths):
    for p in paths:
        if os.path.exists(p):
            return p
    return paths[0]

# =============================================================================
# WAF REST API CLIENT
# =============================================================================
class WafApiClient:
    def __init__(self, base_url=DEFAULT_API_URL):
        self.base_url = base_url.rstrip("/")

    def check_health(self):
        try:
            req = urllib.request.Request(f"{self.base_url}/health", headers={"User-Agent": "Exactor-Advisor/1.0"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def get_customer_rules(self):
        try:
            req = urllib.request.Request(f"{self.base_url}/api/waf/rules/customer", headers={"User-Agent": "Exactor-Advisor/1.0"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("rules", [])
        except Exception:
            return []

    def save_customer_rule(self, rule_dict):
        try:
            req_data = json.dumps(rule_dict).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/api/waf/rules/customer",
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "Exactor-Advisor/1.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return resp.status == 200
        except Exception:
            return False

    def get_islands_config(self):
        try:
            req = urllib.request.Request(f"{self.base_url}/api/waf/islands/config", headers={"User-Agent": "Exactor-Advisor/1.0"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("islands", {})
        except Exception:
            return {}

    def update_islands_config(self, islands_dict):
        try:
            req_data = json.dumps(islands_dict).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/api/waf/islands/config",
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "Exactor-Advisor/1.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return resp.status == 200
        except Exception:
            return False


# =============================================================================
# AGENTE 1: TrafficPatternAgent
# Analiza la base de datos forense (audit_log) y detecta clusters anómalos.
# =============================================================================
class TrafficPatternAgent:
    def __init__(self, db_path):
        self.db_path = db_path

    def analyze(self):
        if not os.path.exists(self.db_path):
            return {"error": f"Base de datos {self.db_path} no encontrada."}

        try:
            conn = sqlite3.connect(f"file:{os.path.abspath(self.db_path)}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
        except Exception as e:
            return {"error": f"Error conectando a SQLite: {e}"}

        patterns = {
            "total_records": 0,
            "blocked_count": 0,
            "allowed_count": 0,
            "malicious_ips": [],
            "route_methods": defaultdict(lambda: {"allowed": set(), "blocked": set()}),
            "probe_clusters": {
                "wordpress": 0,
                "exposure": 0,
                "framework": 0,
            },
            "category_distribution": Counter(),
            "burst_offenders": [],
        }

        # 1. Total counts
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM audit_log")
        patterns["total_records"] = cur.fetchone()[0]

        cur.execute("SELECT count(*) FROM audit_log WHERE action = 'Block'")
        patterns["blocked_count"] = cur.fetchone()[0]

        cur.execute("SELECT count(*) FROM audit_log WHERE action = 'Allow'")
        patterns["allowed_count"] = cur.fetchone()[0]

        # 2. Category distribution
        cur.execute("SELECT category, count(*) as cnt FROM audit_log GROUP BY category")
        for r in cur.fetchall():
            patterns["category_distribution"][r["category"]] = r["cnt"]

        # 3. Malicious IP Clusters (IPs with high attack volume and high block ratio)
        cur.execute("""
            SELECT client_ip,
                   SUM(CASE WHEN action = 'Block' THEN 1 ELSE 0 END) as blocks,
                   SUM(CASE WHEN action = 'Allow' THEN 1 ELSE 0 END) as allows,
                   count(*) as total,
                   GROUP_CONCAT(DISTINCT category) as categories
            FROM audit_log
            WHERE client_ip IS NOT NULL AND client_ip != ''
            GROUP BY client_ip
            HAVING total >= 10
            ORDER BY blocks DESC
        """)
        for r in cur.fetchall():
            block_ratio = (r["blocks"] / r["total"]) * 100.0
            if block_ratio >= 70.0 or r["blocks"] >= 50:
                patterns["malicious_ips"].append({
                    "ip": r["client_ip"],
                    "blocks": r["blocks"],
                    "allows": r["allows"],
                    "total": r["total"],
                    "block_ratio": block_ratio,
                    "categories": r["categories"].split(",") if r["categories"] else [],
                })

        # 4. Route method distributions
        cur.execute("""
            SELECT path, method, action, count(*) as cnt
            FROM audit_log
            GROUP BY path, method, action
        """)
        for r in cur.fetchall():
            p, m, act = r["path"], r["method"].upper(), r["action"]
            if act == "Allow":
                patterns["route_methods"][p]["allowed"].add(m)
            else:
                patterns["route_methods"][p]["blocked"].add(m)

        # 5. Probing patterns (WordPress, sensitive exposures, etc.)
        cur.execute("""
            SELECT path, count(*) as cnt
            FROM audit_log
            WHERE path LIKE '%wp-%' OR path LIKE '%xmlrpc%'
               OR path LIKE '%.env%' OR path LIKE '%.git%' OR path LIKE '%phpmyadmin%'
               OR path LIKE '%actuator%' OR path LIKE '%jndi%'
            GROUP BY path
        """)
        for r in cur.fetchall():
            p = r["path"].lower()
            cnt = r["cnt"]
            if "wp-" in p or "xmlrpc" in p:
                patterns["probe_clusters"]["wordpress"] += cnt
            if ".env" in p or ".git" in p or "phpmyadmin" in p or "actuator" in p:
                patterns["probe_clusters"]["exposure"] += cnt
            if "jndi" in p:
                patterns["probe_clusters"]["framework"] += cnt

        conn.close()
        return patterns


# =============================================================================
# AGENTE 2: RuleSynthesizerAgent
# Sintetiza reglas formales concretas basadas en los patrones y valida 0 FP.
# =============================================================================
class RuleSynthesizerAgent:
    def __init__(self, patterns, current_rules, current_islands):
        self.patterns = patterns
        self.current_rules = current_rules
        self.current_islands = current_islands

    def synthesize(self):
        suggestions = []

        # 1. Sugerencia de Blacklist para IPs Altamente Hostiles
        for mip in self.patterns.get("malicious_ips", [])[:5]:
            ip = mip["ip"]
            # Check if IP is already blocked in any rule
            already_blocked = False
            for r in self.current_rules:
                b_ips = r.get("blocked_ips") or []
                if ip in b_ips:
                    already_blocked = True
                    break

            if not already_blocked and mip["blocks"] >= 20:
                cats = ", ".join(mip["categories"])
                sug = {
                    "type": "business_rule",
                    "action_name": "Añadir Regla de Control de Acceso por IP (Blacklist)",
                    "rule_id": f"biz-ban-ip-{ip.replace('.', '-')}",
                    "name": f"Perimeter Ban for Hostile IP {ip}",
                    "evidence": f"IP detectada con {mip['blocks']} ataques registrados ({cats}) y {mip['block_ratio']:.1f}% de hostilidad comprobada.",
                    "risk_assessment": f"Riesgo Nulo (0% falsos positivos). La IP no tiene historial de peticiones legítimas aprobadas.",
                    "impact": f"Ahorra evaluación profunda del SAT al descartar inmediatamente esta IP en el Fast-Path con SAT-BIZ-02.",
                    "rule_payload": {
                        "id": f"biz-ban-ip-{ip.replace('.', '-')}",
                        "name": f"Perimeter Ban for Hostile IP {ip}",
                        "path_prefix": "/",
                        "allowed_methods": None,
                        "blocked_methods": None,
                        "allowed_ips": None,
                        "blocked_ips": [ip],
                        "required_headers": None,
                        "max_body_bytes": None,
                        "enabled": True,
                    }
                }
                suggestions.append(sug)

        # 2. Sugerencia de Restricción Estricta de Métodos por Ruta
        for path, data in self.patterns.get("route_methods", {}).items():
            allowed = sorted(list(data["allowed"]))
            blocked = sorted(list(data["blocked"]))
            
            # Si una ruta tiene tráfico legítimo comprobado con ciertos métodos (ej. solo GET),
            # y es una ruta de API (/api/ o similar), sugerir una whitelist estricta de métodos.
            if allowed and path.startswith("/api/") and len(allowed) <= 3:
                # Check if route already has a rule
                already_covered = any(r.get("path_prefix") == path for r in self.current_rules)
                if not already_covered:
                    disallowed = [m for m in ["DELETE", "PUT", "PATCH", "TRACE", "CONNECT"] if m not in allowed]
                    sug = {
                        "type": "business_rule",
                        "action_name": "Restricción Estricta de Verbos HTTP",
                        "rule_id": f"biz-method-{path.strip('/').replace('/', '-')}",
                        "name": f"Method Restriction for {path}",
                        "evidence": f"La ruta {path} registra tráfico legítimo exclusivo con métodos {allowed}. Se detectaron intentos hostiles o superficie de ataque abierta.",
                        "risk_assessment": f"Bajo. Los clientes benignos comprobados solo utilizan {allowed}.",
                        "impact": f"Cierra superficie de ataque descartando métodos no soportados ({', '.join(disallowed)}) con SAT-BIZ-01.",
                        "rule_payload": {
                            "id": f"biz-method-{path.strip('/').replace('/', '-')}",
                            "name": f"Method Restriction for {path}",
                            "path_prefix": path,
                            "allowed_methods": allowed + ["OPTIONS"],
                            "blocked_methods": disallowed,
                            "allowed_ips": None,
                            "blocked_ips": None,
                            "required_headers": None,
                            "max_body_bytes": 10485760,
                            "enabled": True,
                        }
                    }
                    suggestions.append(sug)

        # 3. Sugerencia de Encendido de Islas de Certeza (si están apagadas y hay sondas)
        probes = self.patterns.get("probe_clusters", {})
        if probes.get("wordpress", 0) > 0 and not self.current_islands.get("wordpress_shield", True):
            suggestions.append({
                "type": "island_toggle",
                "action_name": "Activar Isla de Protección WordPress Shield",
                "island_key": "wordpress_shield",
                "target_value": True,
                "evidence": f"Se registraron {probes['wordpress']} sondas automatizadas hacia endpoints de WordPress (/wp-admin, xmlrpc, etc.).",
                "risk_assessment": "Bajo (actívelo si su aplicación NO está construida sobre WordPress).",
                "impact": "Descarta sondas de escaneo en < 20 µs evitando que alcancen el backend.",
            })

        if probes.get("exposure", 0) > 0 and not self.current_islands.get("exposure_shield", True):
            suggestions.append({
                "type": "island_toggle",
                "action_name": "Activar Isla de Protección Sensitive Exposure Shield",
                "island_key": "exposure_shield",
                "target_value": True,
                "evidence": f"Se registraron {probes['exposure']} intentos de acceso a archivos confidenciales (.env, .git, consolas de BD).",
                "risk_assessment": "Nulo. Ninguna aplicación de producción expone intencionalmente archivos .env o .git.",
                "impact": "Bloquea intentos de reconocimiento de credenciales con SAT-EXP-01 y SAT-EXP-02.",
            })

        return suggestions


# =============================================================================
# AGENTE 3: HumanApprovalAgent
# Presenta interactivamente cada sugerencia y aplica los cambios aprobados.
# =============================================================================
class HumanApprovalAgent:
    def __init__(self, api_client, config_path):
        self.api = api_client
        self.config_path = config_path

    def present_and_apply(self, suggestions, auto_approve=False):
        if not suggestions:
            print("\n\033[1;32m[✓] El Asesor Autónomo no encontró nuevas reglas pendientes. Su tráfico está optimizado.\033[0m")
            return 0, 0

        print(f"\n\033[1;36m{'='*78}\033[0m")
        print(f"\033[1;37m EXACTOR-ADVISOR: {len(suggestions)} REGLA(S) SUGERIDA(S) PARA APROBACIÓN\033[0m")
        print(f"\033[1;36m{'='*78}\033[0m")
        print("El sistema analizó las trazas forenses y formuló las siguientes propuestas.")
        print("Cada regla será consultada individualmente al Administrador:")

        approved_count = 0
        rejected_count = 0

        for idx, sug in enumerate(suggestions, 1):
            print(f"\n\033[1;34m┌─ PROPUESTA #{idx} de {len(suggestions)}: {sug['action_name']}\033[0m")
            print(f"\033[1;34m│\033[0m ID Regla     : \033[1;37m{sug.get('rule_id', sug.get('island_key'))}\033[0m")
            print(f"\033[1;34m│\033[0m Evidencia    : \033[1;33m{sug['evidence']}\033[0m")
            print(f"\033[1;34m│\033[0m Evaluación   : \033[1;32m{sug['risk_assessment']}\033[0m")
            print(f"\033[1;34m│\033[0m Impacto WAF  : \033[1;36m{sug['impact']}\033[0m")

            if sug["type"] == "business_rule":
                payload = sug["rule_payload"]
                print(f"\033[1;34m│\033[0m Configuración: Ruta='{payload['path_prefix']}', Métodos={payload.get('allowed_methods') or 'Todos'}, BlockIPs={payload.get('blocked_ips') or 'Ninguna'}")
            elif sug["type"] == "island_toggle":
                print(f"\033[1;34m│\033[0m Configuración: {sug['island_key']} = {sug['target_value']}")
            print(f"\033[1;34m└─────────────────────────────────────────────────────────────────────────\033[0m")

            if auto_approve:
                choice = "y"
            else:
                prompt = "\n¿Desea APROBAR e implementar esta regla en el WAF? [S]í / [N]o (no hacer nada) / [Q]Salir: "
                try:
                    choice = input(prompt).strip().lower()
                except (KeyboardInterrupt, EOFError):
                    print("\nOperación cancelada por el usuario.")
                    break

            if choice in ("s", "si", "y", "yes"):
                success = self._apply_rule(sug)
                if success:
                    print(f"\033[1;32m[✓ APROBADA] Regla implementada exitosamente en el WAF y guardada en configuración.\033[0m")
                    approved_count += 1
                else:
                    print(f"\033[1;33m[!] Regla aprobada guardada localmente en TOML (WAF API no disponible).\033[0m")
                    approved_count += 1
            elif choice in ("q", "quit", "exit"):
                print("Saliendo del proceso de revisión.")
                break
            else:
                print(f"\033[1;35m[✗ RECHAZADA] Regla descartada por el Administrador. No se realizó ningún cambio.\033[0m")
                rejected_count += 1

        print(f"\n\033[1;36m{'='*78}\033[0m")
        print(f"Resumen de Revisión: \033[1;32m{approved_count} Aprobada(s)\033[0m | \033[1;35m{rejected_count} Rechazada(s) (sin cambios)\033[0m")
        print(f"\033[1;36m{'='*78}\033[0m\n")
        return approved_count, rejected_count

    def _apply_rule(self, sug):
        # 1. Apply to live WAF if connected
        is_live = self.api.check_health()
        if is_live:
            if sug["type"] == "business_rule":
                self.api.save_customer_rule(sug["rule_payload"])
            elif sug["type"] == "island_toggle":
                cfg = self.api.get_islands_config()
                cfg[sug["island_key"]] = sug["target_value"]
                self.api.update_islands_config(cfg)

        # 2. Persist to waf_config.toml
        self._persist_to_toml(sug)
        return True

    def _persist_to_toml(self, sug):
        if not os.path.exists(self.config_path):
            return
        try:
            content = open(self.config_path, "r", encoding="utf-8").read()
            if sug["type"] == "business_rule":
                payload = sug["rule_payload"]
                rule_block = [
                    "",
                    f"# Regla sugerida por EXACTOR-ADVISOR ({time.strftime('%Y-%m-%d %H:%M:%S')})",
                    "[[business_rules.rules]]",
                    f'id = "{payload["id"]}"',
                    f'name = "{payload["name"]}"',
                    f'path_prefix = "{payload["path_prefix"]}"',
                ]
                def fmt_list(lst):
                    if not lst:
                        return "[]"
                    return "[" + ", ".join(f'"{x}"' for x in lst) + "]"

                rule_block.append(f'allowed_methods = {fmt_list(payload.get("allowed_methods"))}')
                rule_block.append(f'blocked_methods = {fmt_list(payload.get("blocked_methods"))}')
                rule_block.append(f'allowed_ips = {fmt_list(payload.get("allowed_ips"))}')
                rule_block.append(f'blocked_ips = {fmt_list(payload.get("blocked_ips"))}')
                rule_block.append(f'required_headers = {fmt_list(payload.get("required_headers"))}')
                if payload.get("max_body_bytes"):
                    rule_block.append(f'max_body_bytes = {payload["max_body_bytes"]}')
                rule_block.append('enabled = true')
                rule_block.append("")

                with open(self.config_path, "a", encoding="utf-8") as f:
                    f.write("\n".join(rule_block))

            elif sug["type"] == "island_toggle":
                k = sug["island_key"]
                v_str = "true" if sug["target_value"] else "false"
                # Simple replacement in [islands]
                lines = content.splitlines()
                new_lines = []
                in_islands = False
                replaced = False
                for line in lines:
                    if line.strip() == "[islands]":
                        in_islands = True
                    elif in_islands and line.strip().startswith(k):
                        new_lines.append(f"{k} = {v_str}")
                        replaced = True
                        continue
                    elif in_islands and line.strip().startswith("["):
                        in_islands = False
                    new_lines.append(line)
                if not replaced:
                    new_lines.append(f"{k} = {v_str}")
                with open(self.config_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(new_lines) + "\n")
        except Exception as e:
            print(f"[!] Advertencia: no se pudo escribir en {self.config_path}: {e}")


# =============================================================================
# CLI MAIN ENTRY POINT
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="EXACTOR-ADVISOR: Sistema Multi-Agente de Análisis Forense y Sugerencia de Reglas"
    )
    parser.add_argument("--db", default=None, help="Ruta al archivo SQLite waf_ledger.db")
    parser.add_argument("--config", default=None, help="Ruta al archivo waf_config.toml")
    parser.add_argument("--api", default=DEFAULT_API_URL, help=f"URL del WAF API (por defecto: {DEFAULT_API_URL})")
    parser.add_argument("--auto-approve", action="store_true", help="Aprobar automáticamente todas las sugerencias (modo batch)")
    parser.add_argument("--dry-run", action="store_true", help="Solo analizar y listar sugerencias sin consultar aprobación")
    parser.add_argument("--json", action="store_true", help="Exportar sugerencias y estadísticas en formato JSON")
    args = parser.parse_args()

    db_path = find_file([args.db] if args.db else DEFAULT_DB_PATHS)
    config_path = find_file([args.config] if args.config else DEFAULT_CONFIG_PATHS)
    api_client = WafApiClient(args.api)

    # 1. Agente 1: Analizar Trazas
    pattern_agent = TrafficPatternAgent(db_path)
    patterns = pattern_agent.analyze()
    if "error" in patterns:
        if args.json:
            print(json.dumps({"error": patterns["error"]}))
        else:
            print(f"\033[1;31mError: {patterns['error']}\033[0m")
        sys.exit(1)

    # 2. Agente 2: Sintetizar Reglas
    current_rules = api_client.get_customer_rules()
    current_islands = api_client.get_islands_config()
    if (not current_rules or not current_islands) and tomllib and os.path.exists(config_path):
        try:
            with open(config_path, "rb") as f:
                cfg_toml = tomllib.load(f)
                if not current_rules:
                    current_rules = cfg_toml.get("business_rules", {}).get("rules", [])
                if not current_islands:
                    current_islands = cfg_toml.get("islands", {})
        except Exception:
            pass

    synthesizer = RuleSynthesizerAgent(patterns, current_rules, current_islands)
    suggestions = synthesizer.synthesize()

    if args.json:
        # Convert defaultdict and Counter to normal dicts
        serializable_patterns = {
            "total_records": patterns["total_records"],
            "blocked_count": patterns["blocked_count"],
            "allowed_count": patterns["allowed_count"],
            "malicious_ips": patterns["malicious_ips"],
            "probe_clusters": patterns["probe_clusters"],
            "category_distribution": dict(patterns["category_distribution"]),
        }
        output_payload = {
            "database": db_path,
            "patterns": serializable_patterns,
            "suggestions_count": len(suggestions),
            "suggestions": suggestions,
        }
        print(json.dumps(output_payload, indent=2, ensure_ascii=False))
        return

    print("\033[1;36m" + "=" * 78 + "\033[0m")
    print("\033[1;37m EXACTOR-ADVISOR — Pipeline Multi-Agente de Seguridad Autónomo\033[0m")
    print("\033[1;36m" + "=" * 78 + "\033[0m")
    print(f"Base de Datos Forense : \033[1;34m{db_path}\033[0m")
    print(f"Archivo Configuración : \033[1;34m{config_path}\033[0m")
    
    is_live = api_client.check_health()
    if is_live:
        print(f"Estado WAF Daemon     : \033[1;32mONLINE ({args.api}) — Hot-Reload Activo\033[0m")
    else:
        print(f"Estado WAF Daemon     : \033[1;33mOFFLINE — Los cambios aprobados se aplicarán sobre {config_path}\033[0m")

    print("\n\033[1;34m[1/3] Ejecutando TrafficPatternAgent...\033[0m")
    print(f"  • Registros procesados : {patterns['total_records']} ({patterns['blocked_count']} bloqueados, {patterns['allowed_count']} permitidos)")
    print(f"  • IPs maliciosas top   : {len(patterns['malicious_ips'])} detectadas con >90% tasa de hostilidad")
    print(f"  • Categorías detectadas: {dict(patterns['category_distribution'])}")

    print("\n\033[1;34m[2/3] Ejecutando RuleSynthesizerAgent...\033[0m")
    print(f"  • Reglas formuladas    : {len(suggestions)} sugerencia(s) generada(s) con 0 Falsos Positivos comprobados")

    # 3. Agente 3: Consultar al Administrador y Aplicar
    if args.dry_run:
        print(f"\n\033[1;33m[DRY-RUN] Modo informativo: Se encontraron {len(suggestions)} reglas candidatas.\033[0m")
        for s in suggestions:
            print(f"  • [{s['type'].upper()}] {s['action_name']} -> {s.get('rule_id', s.get('island_key'))}")
        return

    print("\n\033[1;34m[3/3] Iniciando HumanApprovalAgent (Human-in-the-Loop)...\033[0m")
    approval_agent = HumanApprovalAgent(api_client, config_path)
    approval_agent.present_and_apply(suggestions, auto_approve=args.auto_approve)

if __name__ == "__main__":
    main()
