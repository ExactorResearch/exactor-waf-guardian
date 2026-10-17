#!/usr/bin/env python3
"""
===============================================================================
 EXACTOR-RULES: Administrador Interactivo de Reglas e Islas para EXACTOR WAF
 Interfaz TUI estilo htop/btop en curses para gestión en tiempo real de:
   - Reglas de Negocio del Cliente (Customer Business Rules)
   - Islas de Protección Modulares (WordPress, Exposición, Frameworks)
   - Inspector de Deducción Matemática SAT en Vivo
===============================================================================
"""

import os
import sys
import json
import time
import argparse
import urllib.request
import urllib.error

# Ensure UTF-8 output encoding across all operating systems
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Reducir retraso de tecla ESC para respuesta instantánea en ncurses
os.environ.setdefault("ESCDELAY", "25")

try:
    import curses
    HAVE_CURSES = True
except ImportError:
    HAVE_CURSES = False

DEFAULT_API_URL = os.environ.get("EXACTOR_API_URL", "http://127.0.0.1:10000")
DEFAULT_CONFIG_PATHS = [
    "waf_config.toml",
    "/etc/exactor/waf_config.toml",
    "../waf_config.toml",
    "../../waf_config.toml",
]

def find_config_file(cli_path=None):
    if cli_path and os.path.exists(cli_path):
        return cli_path
    for p in DEFAULT_CONFIG_PATHS:
        if os.path.exists(p):
            return p
    return "waf_config.toml"

def safe_addstr(stdscr, y, x, text, attr=0):
    if not HAVE_CURSES:
        return
    try:
        max_y, max_x = stdscr.getmaxyx()
        if y < 0 or y >= max_y or x < 0 or x >= max_x:
            return
        avail = max_x - x
        if y == max_y - 1:
            avail -= 1
        if avail <= 0:
            return
        stdscr.addstr(y, x, str(text)[:avail], attr)
    except curses.error:
        pass

class WafApiClient:
    def __init__(self, base_url=DEFAULT_API_URL):
        self.base_url = base_url.rstrip("/")

    def _request(self, method, endpoint, data=None, timeout=2.0):
        url = f"{self.base_url}{endpoint}"
        req_data = None
        headers = {"User-Agent": "Exactor-Rules-TUI/1.0"}
        if data is not None:
            req_data = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                body = resp.read().decode("utf-8")
                return status, json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8") if e.fp else ""
            try:
                parsed = json.loads(err_body)
            except Exception:
                parsed = {"error": err_body}
            return e.code, parsed
        except Exception as e:
            return 0, {"error": str(e)}

    def check_health(self):
        status, data = self._request("GET", "/health", timeout=1.0)
        return status == 200, data

    def get_islands_config(self):
        status, data = self._request("GET", "/api/waf/islands/config")
        if status == 200 and "islands" in data:
            return True, data["islands"]
        return False, {}

    def update_islands_config(self, islands_dict):
        status, data = self._request("POST", "/api/waf/islands/config", data=islands_dict)
        return status == 200, data

    def get_customer_rules(self):
        status, data = self._request("GET", "/api/waf/rules/customer")
        if status == 200 and "rules" in data:
            return True, data["rules"]
        return False, []

    def save_customer_rule(self, rule_dict):
        status, data = self._request("POST", "/api/waf/rules/customer", data=rule_dict)
        return status == 200, data

    def delete_customer_rule(self, rule_id):
        status, data = self._request("DELETE", f"/api/waf/rules/customer/{rule_id}")
        return status == 200, data

    def inspect_payload(self, method, path, query_string="", body=""):
        payload = {
            "method": method,
            "path": path,
            "query_string": query_string,
            "body": body,
            "headers": {},
        }
        status, data = self._request("POST", "/api/waf/inspect", data=payload)
        return status == 200, data


class ExactorRulesApp:
    def __init__(self, api_url=DEFAULT_API_URL, config_path=None):
        self.api = WafApiClient(api_url)
        self.config_path = find_config_file(config_path)
        self.active_tab = 0  # 0: Customer Rules, 1: Protection Islands, 2: Simulator
        self.is_connected = False
        self.connection_msg = "Conectando..."
        
        # State
        self.rules = []
        self.islands = {
            "wordpress_shield": True,
            "exposure_shield": True,
            "framework_shield": True,
        }
        self.selected_rule_idx = 0
        self.selected_island_idx = 0
        self.scroll_offset = 0
        self.status_message = "Listo."
        self.status_time = time.time()
        
        # Inspection simulator state
        self.sim_method = "GET"
        self.sim_path = "/api/v1/users"
        self.sim_body = ""
        self.sim_result = None

    def set_status(self, msg):
        self.status_message = msg
        self.status_time = time.time()

    def sync_data(self):
        healthy, h_data = self.api.check_health()
        self.is_connected = healthy
        if healthy:
            self.connection_msg = f"ONLINE ({self.api.base_url})"
            ok_r, r_data = self.api.get_customer_rules()
            if ok_r:
                self.rules = r_data
            ok_i, i_data = self.api.get_islands_config()
            if ok_i:
                self.islands = i_data
        else:
            self.connection_msg = f"OFFLINE ({self.api.base_url})"
            self.load_from_toml()

    def load_from_toml(self):
        if not os.path.exists(self.config_path):
            return
        try:
            content = open(self.config_path, "r", encoding="utf-8").read()
            in_islands = False
            in_biz_rule = False
            cur_rule = {}
            parsed_rules = []
            
            for line in content.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if s == "[islands]":
                    in_islands = True
                    in_biz_rule = False
                    continue
                elif s == "[[business_rules.rules]]":
                    if cur_rule and "id" in cur_rule:
                        parsed_rules.append(cur_rule)
                    cur_rule = {"enabled": True}
                    in_biz_rule = True
                    in_islands = False
                    continue
                elif s.startswith("["):
                    if cur_rule and "id" in cur_rule:
                        parsed_rules.append(cur_rule)
                    cur_rule = {}
                    in_islands = False
                    in_biz_rule = False
                    continue
                
                if in_islands and "=" in s:
                    k, v = [x.strip() for x in s.split("=", 1)]
                    val = v.lower().startswith("true")
                    if k in self.islands:
                        self.islands[k] = val
                elif in_biz_rule and "=" in s:
                    k, v = [x.strip() for x in s.split("=", 1)]
                    if k == "id":
                        cur_rule["id"] = v.strip('"\'')
                    elif k == "name":
                        cur_rule["name"] = v.strip('"\'')
                    elif k == "path_prefix":
                        cur_rule["path_prefix"] = v.strip('"\'')
                    elif k == "enabled":
                        cur_rule["enabled"] = v.lower().startswith("true")
                    elif k == "max_body_bytes":
                        try:
                            cur_rule["max_body_bytes"] = int(v.split("#")[0].strip())
                        except Exception:
                            pass
                    elif k in ["allowed_methods", "blocked_methods", "allowed_ips", "blocked_ips", "required_headers"]:
                        if "[" in v and "]" in v:
                            inner = v[v.find("[") + 1 : v.rfind("]")]
                            items = [x.strip().strip('"\'') for x in inner.split(",") if x.strip()]
                            cur_rule[k] = items
            
            if cur_rule and "id" in cur_rule:
                parsed_rules.append(cur_rule)
            self.rules = parsed_rules
        except Exception as e:
            self.set_status(f"Error cargando TOML: {e}")

    def save_to_toml(self):
        try:
            lines = [
                "# ==============================================================================",
                "# EXACTOR WAF GUARDIAN - CONFIGURATION PERSISTED BY EXACTOR-RULES TUI",
                f"# Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                "# ==============================================================================",
                "",
                "[islands]",
                f"wordpress_shield = {'true' if self.islands.get('wordpress_shield', True) else 'false'}",
                f"exposure_shield = {'true' if self.islands.get('exposure_shield', True) else 'false'}",
                f"framework_shield = {'true' if self.islands.get('framework_shield', True) else 'false'}",
                "",
                "[business_rules]",
                "enabled = true",
                "",
            ]
            for r in self.rules:
                lines.append("[[business_rules.rules]]")
                lines.append(f'id = "{r.get("id", "")}"')
                lines.append(f'name = "{r.get("name", "")}"')
                if r.get("path_prefix"):
                    lines.append(f'path_prefix = "{r.get("path_prefix")}"')
                else:
                    lines.append('path_prefix = "/"')
                
                def fmt_list(lst):
                    if not lst:
                        return "[]"
                    items = ', '.join(f'"{x}"' for x in lst)
                    return f"[{items}]"

                lines.append(f'allowed_methods = {fmt_list(r.get("allowed_methods", []))}')
                lines.append(f'blocked_methods = {fmt_list(r.get("blocked_methods", []))}')
                lines.append(f'allowed_ips = {fmt_list(r.get("allowed_ips", []))}')
                lines.append(f'blocked_ips = {fmt_list(r.get("blocked_ips", []))}')
                lines.append(f'required_headers = {fmt_list(r.get("required_headers", []))}')
                if r.get("max_body_bytes") is not None:
                    lines.append(f'max_body_bytes = {r.get("max_body_bytes")}')
                lines.append(f'enabled = {"true" if r.get("enabled", True) else "false"}')
                lines.append("")

            with open(self.config_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            self.set_status(f"Guardado exitoso en {self.config_path}")
        except Exception as e:
            self.set_status(f"Fallo al guardar TOML: {e}")

    # =========================================================================
    # CURSES TUI IMPLEMENTATION
    # =========================================================================
    def run_curses(self, stdscr):
        curses.curs_set(0)
        stdscr.timeout(500)
        self.init_colors()
        self.sync_data()

        while True:
            self.render(stdscr)
            try:
                ch = stdscr.getch()
            except KeyboardInterrupt:
                break

            if ch == -1:
                continue
            if ch in (ord('q'), ord('Q')):
                break
            elif ch == ord('\t'):
                self.active_tab = (self.active_tab + 1) % 3
                self.scroll_offset = 0
            elif ch in (ord('1'), ord('2'), ord('3')):
                self.active_tab = ch - ord('1')
                self.scroll_offset = 0
            elif ch == curses.KEY_UP:
                self.handle_up()
            elif ch == curses.KEY_DOWN:
                self.handle_down()
            elif ch in (ord(' '), ord('t'), ord('T')):
                self.handle_toggle()
            elif ch in (ord('a'), ord('A')):
                if self.active_tab == 0:
                    self.show_add_rule_dialog(stdscr)
            elif ch in (ord('d'), ord('D'), curses.KEY_DC):
                if self.active_tab == 0:
                    self.handle_delete_rule(stdscr)
            elif ch in (ord('e'), ord('E'), 10, 13):
                if self.active_tab == 0:
                    self.show_rule_detail_dialog(stdscr)
                elif self.active_tab == 1:
                    self.handle_toggle()
            elif ch in (ord('s'), ord('S')):
                self.save_to_toml()
            elif ch in (ord('r'), ord('R')):
                self.sync_data()
                self.set_status("Datos sincronizados.")
            elif ch in (ord('p'), ord('P')):
                self.show_simulator_dialog(stdscr)

    def init_colors(self):
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_RED, -1)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_GREEN)
        curses.init_pair(9, curses.COLOR_WHITE, curses.COLOR_RED)

    def handle_up(self):
        if self.active_tab == 0:
            if self.selected_rule_idx > 0:
                self.selected_rule_idx -= 1
                if self.selected_rule_idx < self.scroll_offset:
                    self.scroll_offset = self.selected_rule_idx
        elif self.active_tab == 1:
            if self.selected_island_idx > 0:
                self.selected_island_idx -= 1

    def handle_down(self):
        if self.active_tab == 0:
            if self.selected_rule_idx < len(self.rules) - 1:
                self.selected_rule_idx += 1
        elif self.active_tab == 1:
            if self.selected_island_idx < 2:
                self.selected_island_idx += 1

    def handle_toggle(self):
        if self.active_tab == 0:
            if 0 <= self.selected_rule_idx < len(self.rules):
                rule = self.rules[self.selected_rule_idx]
                rule["enabled"] = not rule.get("enabled", True)
                if self.is_connected:
                    self.api.save_customer_rule(rule)
                self.set_status(f"Regla '{rule['id']}' conmutada a {'ACTIVA' if rule['enabled'] else 'INACTIVA'}.")
        elif self.active_tab == 1:
            keys = ["wordpress_shield", "exposure_shield", "framework_shield"]
            target_key = keys[self.selected_island_idx]
            new_val = not self.islands.get(target_key, True)
            self.islands[target_key] = new_val
            if self.is_connected:
                self.api.update_islands_config(self.islands)
            self.set_status(f"Isla '{target_key}' conmutada a {'ACTIVADA' if new_val else 'DESACTIVADA'}.")

    def handle_delete_rule(self, stdscr):
        if not (0 <= self.selected_rule_idx < len(self.rules)):
            return
        rule = self.rules[self.selected_rule_idx]
        rid = rule.get("id", "desconocida")
        
        max_y, max_x = stdscr.getmaxyx()
        prompt = f"¿Eliminar regla '{rid}'? [y/N]: "
        safe_addstr(stdscr, max_y - 2, 2, prompt, curses.color_pair(3) | curses.A_BOLD)
        stdscr.refresh()
        
        curses.echo()
        curses.curs_set(1)
        resp = stdscr.getstr(max_y - 2, len(prompt) + 2, 4).decode("utf-8").strip().lower()
        curses.noecho()
        curses.curs_set(0)
        
        if resp in ("y", "yes", "s", "si"):
            if self.is_connected:
                self.api.delete_customer_rule(rid)
            self.rules.pop(self.selected_rule_idx)
            if self.selected_rule_idx >= len(self.rules) and self.selected_rule_idx > 0:
                self.selected_rule_idx -= 1
            self.set_status(f"Regla '{rid}' eliminada.")
        else:
            self.set_status("Operación de eliminación cancelada.")

    def render(self, stdscr):
        stdscr.clear()
        max_y, max_x = stdscr.getmaxyx()
        if max_y < 12 or max_x < 60:
            safe_addstr(stdscr, 0, 0, "Terminal demasiado pequeño para EXACTOR-RULES.", curses.color_pair(2))
            return

        title = " EXACTOR-RULES v0.1.0 — Deterministic SAT Cyber-Defense Control Plane "
        safe_addstr(stdscr, 0, 0, title.ljust(max_x), curses.color_pair(7) | curses.A_BOLD)

        status_color = curses.color_pair(1) if self.is_connected else curses.color_pair(2)
        safe_addstr(stdscr, 1, 2, f"Motor WAF: {self.connection_msg}", status_color | curses.A_BOLD)
        safe_addstr(stdscr, 1, 40, f"Config TOML: {self.config_path}", curses.color_pair(4))

        tab_y = 3
        tabs = [
            (" [1] Reglas de Negocio (Customer) ", 0),
            (" [2] Islas de Certeza (Islands) ", 1),
            (" [3] Inspector / Simulador SAT ", 2),
        ]
        curr_x = 2
        for title_str, idx in tabs:
            if idx == self.active_tab:
                attr = curses.color_pair(7) | curses.A_BOLD
            else:
                attr = curses.color_pair(4)
            safe_addstr(stdscr, tab_y, curr_x, title_str, attr)
            curr_x += len(title_str) + 2

        safe_addstr(stdscr, 4, 0, "─" * max_x, curses.color_pair(4))

        if self.active_tab == 0:
            self.render_customer_rules(stdscr, 5, max_y - 3, max_x)
        elif self.active_tab == 1:
            self.render_islands_view(stdscr, 5, max_y - 3, max_x)
        elif self.active_tab == 2:
            self.render_simulator_view(stdscr, 5, max_y - 3, max_x)

        status_y = max_y - 2
        safe_addstr(stdscr, status_y, 0, " " * max_x, curses.color_pair(4))
        safe_addstr(stdscr, status_y, 2, f"Mensaje: {self.status_message}", curses.color_pair(3) | curses.A_BOLD)

        footer_y = max_y - 1
        keys_help = "TAB: Cambiar Vista | Espacio/T: Toggle | A: Añadir | D: Eliminar | E: Detalle | P: Probar | S: Guardar TOML | Q: Salir"
        safe_addstr(stdscr, footer_y, 0, keys_help.ljust(max_x), curses.color_pair(6) | curses.A_BOLD)

    def render_customer_rules(self, stdscr, start_y, end_y, max_x):
        header = f" {'ID':<20s} {'ESTADO':<10s} {'RUTA':<20s} {'MÉTODOS PERMITIDOS':<22s} {'RESTRICCIÓN IP / ENCABEZADO':<30s}"
        safe_addstr(stdscr, start_y, 0, header.ljust(max_x), curses.color_pair(4) | curses.A_BOLD)

        avail_rows = end_y - start_y - 1
        if not self.rules:
            safe_addstr(stdscr, start_y + 2, 4, "No hay reglas de negocio definidas. Presione [A] para añadir una nueva.", curses.color_pair(3))
            return

        if self.selected_rule_idx >= self.scroll_offset + avail_rows:
            self.scroll_offset = self.selected_rule_idx - avail_rows + 1
        if self.selected_rule_idx < self.scroll_offset:
            self.scroll_offset = self.selected_rule_idx

        for i in range(avail_rows):
            rule_idx = self.scroll_offset + i
            if rule_idx >= len(self.rules):
                break
            r = self.rules[rule_idx]
            y = start_y + 1 + i
            is_selected = (rule_idx == self.selected_rule_idx)

            rid = r.get("id", f"rule-{rule_idx}")[:19]
            enabled = r.get("enabled", True)
            status_badge = "[ ACTIVA ]" if enabled else "[ INACT. ]"
            path = r.get("path_prefix", "*")[:19]
            
            allowed = r.get("allowed_methods")
            methods_str = ", ".join(allowed) if allowed else "TODOS"
            methods_str = methods_str[:21]

            ips = r.get("allowed_ips")
            hdrs = r.get("required_headers")
            constraints = []
            if ips:
                constraints.append(f"IP: {','.join(ips)}")
            if hdrs:
                constraints.append(f"Hdr: {','.join(hdrs)}")
            if r.get("max_body_bytes"):
                constraints.append(f"Max: {r['max_body_bytes']}B")
            const_str = " | ".join(constraints) if constraints else "Sin restricciones IP/Hdr"
            const_str = const_str[:29]

            line_str = f" {rid:<20s} {status_badge:<10s} {path:<20s} {methods_str:<22s} {const_str:<30s}"
            
            if is_selected:
                safe_addstr(stdscr, y, 0, line_str.ljust(max_x), curses.color_pair(6) | curses.A_BOLD)
            else:
                attr = curses.color_pair(1) if enabled else curses.color_pair(2)
                safe_addstr(stdscr, y, 0, line_str.ljust(max_x), attr)

    def render_islands_view(self, stdscr, start_y, end_y, max_x):
        safe_addstr(stdscr, start_y, 2, "ISLAS DE CERTEZA MODULARES (Certainty Islands Toggle)", curses.color_pair(4) | curses.A_BOLD)
        safe_addstr(stdscr, start_y + 1, 2, "Las islas activas evalúan en caliente y descartan automáticamente tráfico hostil con latencia < 50 µs.", curses.color_pair(3))

        islands_meta = [
            (
                "wordpress_shield",
                "ISLAND-WORDPRESS",
                "WordPress Scanner & Exploit Shield",
                "Bloquea rastreadores de /wp-admin, /wp-login.php, xmlrpc.php, etc.",
                "Desactivar SÓLO si este servidor aloja legítimamente WordPress."
            ),
            (
                "exposure_shield",
                "ISLAND-EXPOSURE",
                "Sensitive Files & Backdoor Shield",
                "Bloquea sondeos a /.env, /.git, phpMyAdmin, actuator, volcados SQL.",
                "Impide el reconocimiento de credenciales y consolas sin autenticar."
            ),
            (
                "framework_shield",
                "ISLAND-FRAMEWORK",
                "Modern Framework Exploits Shield",
                "Bloquea inyecciones Log4j/JNDI (${jndi:...}), Spring SpEL, Laravel Ignition.",
                "Detiene intentos de ejecución remota dirigidos a frameworks empresariales."
            ),
        ]

        card_y = start_y + 3
        for idx, (key, island_id, title, desc, hint) in enumerate(islands_meta):
            enabled = self.islands.get(key, True)
            is_selected = (idx == self.selected_island_idx)
            
            box_attr = curses.color_pair(6) if is_selected else curses.color_pair(4)
            badge_attr = curses.color_pair(8) if enabled else curses.color_pair(9)
            badge_text = " [ ACTIVA / BLINDAJE ON ] " if enabled else " [ DESACTIVADA / PERMITE PROBES ] "

            safe_addstr(stdscr, card_y, 4, f"{'->' if is_selected else '  '} {island_id} :: {title}", box_attr | curses.A_BOLD)
            safe_addstr(stdscr, card_y, 60, badge_text, badge_attr | curses.A_BOLD)
            safe_addstr(stdscr, card_y + 1, 8, desc, curses.color_pair(1) if enabled else curses.color_pair(2))
            safe_addstr(stdscr, card_y + 2, 8, f"Nota: {hint}", curses.color_pair(3))
            safe_addstr(stdscr, card_y + 3, 4, "─" * (max_x - 8), curses.color_pair(4))

            card_y += 4

        safe_addstr(stdscr, card_y + 1, 4, "[!] Use las flechas Arriba/Abajo y presione [ESPACIO] o [ENTER] para conmutar cualquier escudo.", curses.color_pair(3) | curses.A_BOLD)

    def render_simulator_view(self, stdscr, start_y, end_y, max_x):
        safe_addstr(stdscr, start_y, 2, "INSPECTOR / SIMULADOR DE VERIFICACIÓN SAT EN VIVO", curses.color_pair(4) | curses.A_BOLD)
        safe_addstr(stdscr, start_y + 1, 2, "Simule peticiones HTTP contra el motor formal y verifique la deducción matemática generada.", curses.color_pair(3))

        safe_addstr(stdscr, start_y + 3, 4, f"Método HTTP : {self.sim_method}", curses.color_pair(1) | curses.A_BOLD)
        safe_addstr(stdscr, start_y + 4, 4, f"Ruta / URI  : {self.sim_path}", curses.color_pair(4) | curses.A_BOLD)
        safe_addstr(stdscr, start_y + 5, 4, f"Cuerpo/Body : {self.sim_body if self.sim_body else '(Vacío)'}", curses.color_pair(5))
        safe_addstr(stdscr, start_y + 6, 4, "[ Presione 'P' para editar y ejecutar prueba ]", curses.color_pair(3))

        if self.sim_result:
            safe_addstr(stdscr, start_y + 8, 2, "── RESULTADO DE EVALUACIÓN FORMAL ──", curses.color_pair(4) | curses.A_BOLD)
            is_vio = self.sim_result.get("is_violation", False)
            act = self.sim_result.get("action", "ALLOW")
            cat = self.sim_result.get("category", "BENIGN")
            lat = self.sim_result.get("execution_time_us", 0.0)

            act_attr = curses.color_pair(9) if act == "BLOCK" else curses.color_pair(8)
            safe_addstr(stdscr, start_y + 10, 4, f"DECISIÓN FINAL : {act} [{cat}]", act_attr | curses.A_BOLD)
            safe_addstr(stdscr, start_y + 11, 4, f"Latencia SAT   : {lat:.2f} µs (Microsegundos)", curses.color_pair(1) | curses.A_BOLD)
            
            rules = self.sim_result.get("matched_rules", [])
            r_str = ", ".join(r.get("rule_id", "") for r in rules) if rules else "Ninguna (Tráfico Benigno)"
            safe_addstr(stdscr, start_y + 12, 4, f"Reglas Disparadas: {r_str}", curses.color_pair(3) | curses.A_BOLD)

            causal = self.sim_result.get("causal_proof", "N/A")
            safe_addstr(stdscr, start_y + 13, 4, f"Prueba Causal   : {causal}", curses.color_pair(4))

            deductions = self.sim_result.get("deduction_steps", [])
            safe_addstr(stdscr, start_y + 15, 4, "Pasos Deductivos del SAT Solver:", curses.color_pair(4) | curses.A_BOLD)
            for d_idx, step in enumerate(deductions[:5]):
                safe_addstr(stdscr, start_y + 16 + d_idx, 6, f"• {step}", curses.color_pair(1))

    def show_simulator_dialog(self, stdscr):
        max_y, max_x = stdscr.getmaxyx()
        win_h, win_w = 12, min(70, max_x - 4)
        top_y, top_x = (max_y - win_h) // 2, (max_x - win_w) // 2
        
        dialog = curses.newwin(win_h, win_w, top_y, top_x)
        dialog.box()
        safe_addstr(dialog, 0, 2, " SIMULADOR SAT - PARÁMETROS ", curses.color_pair(7) | curses.A_BOLD)
        safe_addstr(dialog, 2, 4, "Método HTTP (GET/POST/DELETE/etc):", curses.color_pair(4))
        safe_addstr(dialog, 4, 4, "Ruta / URI Path (ej. /wp-login.php):", curses.color_pair(4))
        safe_addstr(dialog, 6, 4, "Body (opcional, ej. ${jndi:ldap:...}):", curses.color_pair(4))
        safe_addstr(dialog, 10, 4, "[Enter para Ejecutar | ESC para Cancelar]", curses.color_pair(3))
        dialog.refresh()

        curses.echo()
        curses.curs_set(1)
        
        safe_addstr(dialog, 3, 6, " " * (win_w - 12))
        m = dialog.getstr(3, 6, 10).decode("utf-8").strip().upper() or self.sim_method
        
        safe_addstr(dialog, 5, 6, " " * (win_w - 12))
        p = dialog.getstr(5, 6, win_w - 14).decode("utf-8").strip() or self.sim_path
        
        safe_addstr(dialog, 7, 6, " " * (win_w - 12))
        b = dialog.getstr(7, 6, win_w - 14).decode("utf-8").strip() or self.sim_body
        
        curses.noecho()
        curses.curs_set(0)

        self.sim_method = m
        self.sim_path = p
        self.sim_body = b
        self.active_tab = 2

        if self.is_connected:
            ok, res = self.api.inspect_payload(m, p, "", b)
            if ok:
                self.sim_result = res
                self.set_status("Inspección SAT completada exitosamente.")
            else:
                self.set_status("Error al comunicar con /api/waf/inspect.")
        else:
            self.set_status("WAF offline: Conecte el WAF para ejecutar simulaciones en vivo.")

    def show_add_rule_dialog(self, stdscr):
        max_y, max_x = stdscr.getmaxyx()
        win_h, win_w = 16, min(75, max_x - 4)
        top_y, top_x = (max_y - win_h) // 2, (max_x - win_w) // 2

        dialog = curses.newwin(win_h, win_w, top_y, top_x)
        dialog.box()
        safe_addstr(dialog, 0, 2, " AÑADIR NUEVA REGLA DE NEGOCIO ", curses.color_pair(7) | curses.A_BOLD)
        safe_addstr(dialog, 2, 4, "ID de la Regla (ej. rule-api-guard):", curses.color_pair(4))
        safe_addstr(dialog, 4, 4, "Nombre Descriptivo:", curses.color_pair(4))
        safe_addstr(dialog, 6, 4, "Prefijo de Ruta (ej. /api/v1/):", curses.color_pair(4))
        safe_addstr(dialog, 8, 4, "Métodos Permitidos (ej. GET,POST o vacío):", curses.color_pair(4))
        safe_addstr(dialog, 10, 4, "IPs Permitidas Whitelist (separadas por coma):", curses.color_pair(4))
        safe_addstr(dialog, 12, 4, "Encabezado Obligatorio (ej. X-Tenant-ID o vacío):", curses.color_pair(4))
        safe_addstr(dialog, 14, 4, "[Enter para Guardar | ESC para Cancelar]", curses.color_pair(3))
        dialog.refresh()

        curses.echo()
        curses.curs_set(1)

        rid = dialog.getstr(3, 6, 25).decode("utf-8").strip()
        if not rid:
            curses.noecho()
            curses.curs_set(0)
            self.set_status("Creación cancelada: Se requiere un ID de regla.")
            return

        name = dialog.getstr(5, 6, 40).decode("utf-8").strip() or rid
        path = dialog.getstr(7, 6, 40).decode("utf-8").strip() or "/"
        methods_str = dialog.getstr(9, 6, 30).decode("utf-8").strip()
        ips_str = dialog.getstr(11, 6, 30).decode("utf-8").strip()
        hdr_str = dialog.getstr(13, 6, 30).decode("utf-8").strip()

        curses.noecho()
        curses.curs_set(0)

        new_rule = {
            "id": rid,
            "name": name,
            "path_prefix": path,
            "allowed_methods": [m.strip().upper() for m in methods_str.split(",") if m.strip()] if methods_str else None,
            "blocked_methods": None,
            "allowed_ips": [ip.strip() for ip in ips_str.split(",") if ip.strip()] if ips_str else None,
            "blocked_ips": None,
            "required_headers": [h.strip() for h in hdr_str.split(",") if h.strip()] if hdr_str else None,
            "max_body_bytes": None,
            "enabled": True,
        }

        if self.is_connected:
            self.api.save_customer_rule(new_rule)
        
        self.rules = [r for r in self.rules if r.get("id") != rid]
        self.rules.append(new_rule)
        self.set_status(f"Regla '{rid}' creada exitosamente.")

    def show_rule_detail_dialog(self, stdscr):
        if not (0 <= self.selected_rule_idx < len(self.rules)):
            return
        rule = self.rules[self.selected_rule_idx]

        max_y, max_x = stdscr.getmaxyx()
        win_h, win_w = 16, min(75, max_x - 4)
        top_y, top_x = (max_y - win_h) // 2, (max_x - win_w) // 2

        dialog = curses.newwin(win_h, win_w, top_y, top_x)
        dialog.box()
        safe_addstr(dialog, 0, 2, f" DETALLE DE REGLA: {rule.get('id')} ", curses.color_pair(7) | curses.A_BOLD)
        
        safe_addstr(dialog, 2, 4, f"Nombre          : {rule.get('name')}", curses.color_pair(1))
        safe_addstr(dialog, 3, 4, f"Prefijo Ruta    : {rule.get('path_prefix')}", curses.color_pair(4))
        safe_addstr(dialog, 4, 4, f"Estado          : {'ACTIVA' if rule.get('enabled', True) else 'INACTIVA'}", curses.color_pair(1) if rule.get('enabled', True) else curses.color_pair(2))
        safe_addstr(dialog, 5, 4, f"Métodos Perm.   : {rule.get('allowed_methods') or 'Todos'}", curses.color_pair(4))
        safe_addstr(dialog, 6, 4, f"Métodos Bloq.   : {rule.get('blocked_methods') or 'Ninguno'}", curses.color_pair(2))
        safe_addstr(dialog, 7, 4, f"IPs Whitelist   : {rule.get('allowed_ips') or 'Sin restricción'}", curses.color_pair(4))
        safe_addstr(dialog, 8, 4, f"IPs Blacklist   : {rule.get('blocked_ips') or 'Sin restricción'}", curses.color_pair(2))
        safe_addstr(dialog, 9, 4, f"Encab. Exigidos : {rule.get('required_headers') or 'Ninguno'}", curses.color_pair(3))
        safe_addstr(dialog, 10, 4, f"Max Payload (B) : {rule.get('max_body_bytes') or 'Ilimitado'}", curses.color_pair(5))
        safe_addstr(dialog, 12, 4, "Regla SAT Base  : SAT-BIZ-01 a SAT-BIZ-04 (Evaluación O(1))", curses.color_pair(3))
        safe_addstr(dialog, 14, 4, "[ Presione cualquier tecla para cerrar ]", curses.color_pair(6) | curses.A_BOLD)
        dialog.refresh()

        dialog.getch()

    # =========================================================================
    # ANSI CONSOLE FALLBACK (For environments without curses)
    # =========================================================================
    def run_cli_fallback(self):
        print("\033[1;36m" + "=" * 78 + "\033[0m")
        print("\033[1;37m EXACTOR-RULES v0.1.0 — Consola de Control de Reglas WAF\033[0m")
        print("\033[1;36m" + "=" * 78 + "\033[0m")
        self.sync_data()
        print(f"Estado WAF  : \033[1;32m{self.connection_msg}\033[0m" if self.is_connected else f"Estado WAF  : \033[1;31m{self.connection_msg}\033[0m")
        print(f"Config TOML : \033[1;34m{self.config_path}\033[0m")
        print("\n\033[1;33m(Tip: Para abrir la interfaz interactiva gráfica TUI estilo htop, instale 'pip install windows-curses' o ejecute en Linux/macOS)\033[0m\n")

        while True:
            print("\033[1;34mOPCIONES:\033[0m")
            print("  1. Listar Reglas de Negocio del Cliente")
            print("  2. Conmutar (Activar/Desactivar) una Regla")
            print("  3. Añadir Nueva Regla de Negocio")
            print("  4. Eliminar una Regla")
            print("  5. Ver y Conmutar Islas de Certeza (WordPress, Exposición, Frameworks)")
            print("  6. Simular Petición / Inspección SAT")
            print("  7. Guardar cambios en waf_config.toml")
            print("  8. Recargar datos")
            print("  0. Salir")
            
            try:
                opc = input("\nSeleccione una opción [0-8]: ").strip()
            except (KeyboardInterrupt, EOFError):
                break

            if opc == "0":
                break
            elif opc == "1":
                self._cli_list_rules()
            elif opc == "2":
                self._cli_toggle_rule()
            elif opc == "3":
                self._cli_add_rule()
            elif opc == "4":
                self._cli_delete_rule()
            elif opc == "5":
                self._cli_islands()
            elif opc == "6":
                self._cli_simulator()
            elif opc == "7":
                self.save_to_toml()
                print(f"\033[1;32m[OK] Guardado en {self.config_path}\033[0m\n")
            elif opc == "8":
                self.sync_data()
                print("\033[1;32m[OK] Datos sincronizados con el WAF.\033[0m\n")

    def _cli_list_rules(self):
        print(f"\n\033[1;36m{'#':<3s} {'ID':<22s} {'ESTADO':<10s} {'RUTA':<20s} {'METODOS':<20s}\033[0m")
        print("-" * 78)
        if not self.rules:
            print("  (No hay reglas de negocio definidas)")
        for idx, r in enumerate(self.rules, 1):
            st = "\033[1;32mACTIVA\033[0m" if r.get("enabled", True) else "\033[1;31mINACT.\033[0m"
            m = ", ".join(r.get("allowed_methods") or ["TODOS"])
            print(f"{idx:<3d} {r.get('id',''):<22s} {st:<18s} {r.get('path_prefix','/'):<20s} {m:<20s}")
        print()

    def _cli_toggle_rule(self):
        self._cli_list_rules()
        rid = input("Ingrese el ID de la regla a conmutar: ").strip()
        for r in self.rules:
            if r.get("id") == rid:
                r["enabled"] = not r.get("enabled", True)
                if self.is_connected:
                    self.api.save_customer_rule(r)
                print(f"\033[1;32m[OK] Regla '{rid}' ahora esta {'ACTIVA' if r['enabled'] else 'INACTIVA'}.\033[0m\n")
                return
        print("\033[1;31m[X] Regla no encontrada.\033[0m\n")

    def _cli_add_rule(self):
        print("\n\033[1;34m-- Anadir Nueva Regla de Negocio --\033[0m")
        rid = input("ID de la Regla (ej. rule-api-auth): ").strip()
        if not rid:
            print("Cancelado: Se requiere ID.")
            return
        name = input("Nombre descriptivo: ").strip() or rid
        path = input("Prefijo de ruta (ej. /api/v1/): ").strip() or "/"
        methods_raw = input("Metodos permitidos (separados por coma, ej. GET,POST o vacio para todos): ").strip()
        ips_raw = input("IPs autorizadas Whitelist (separadas por coma, o vacio): ").strip()
        hdr_raw = input("Encabezado obligatorio (ej. X-Tenant-ID o vacio): ").strip()

        new_rule = {
            "id": rid,
            "name": name,
            "path_prefix": path,
            "allowed_methods": [m.strip().upper() for m in methods_raw.split(",") if m.strip()] if methods_raw else None,
            "blocked_methods": None,
            "allowed_ips": [ip.strip() for ip in ips_raw.split(",") if ip.strip()] if ips_raw else None,
            "blocked_ips": None,
            "required_headers": [h.strip() for h in hdr_raw.split(",") if h.strip()] if hdr_raw else None,
            "max_body_bytes": None,
            "enabled": True,
        }
        if self.is_connected:
            self.api.save_customer_rule(new_rule)
        self.rules = [r for r in self.rules if r.get("id") != rid]
        self.rules.append(new_rule)
        print(f"\033[1;32m[OK] Regla '{rid}' registrada exitosamente.\033[0m\n")

    def _cli_delete_rule(self):
        self._cli_list_rules()
        rid = input("Ingrese el ID de la regla a eliminar: ").strip()
        for idx, r in enumerate(self.rules):
            if r.get("id") == rid:
                confirm = input(f"Confirmar eliminacion de '{rid}'? [y/N]: ").strip().lower()
                if confirm in ("y", "yes", "s", "si"):
                    if self.is_connected:
                        self.api.delete_customer_rule(rid)
                    self.rules.pop(idx)
                    print(f"\033[1;32m[OK] Regla '{rid}' eliminada.\033[0m\n")
                return
        print("\033[1;31m[X] Regla no encontrada.\033[0m\n")

    def _cli_islands(self):
        print("\n\033[1;36m-- ESTADO DE ISLAS DE CERTEZA --\033[0m")
        for key in ["wordpress_shield", "exposure_shield", "framework_shield"]:
            val = self.islands.get(key, True)
            st = "\033[1;32m[ ACTIVADA / ESCUDO ON ]\033[0m" if val else "\033[1;31m[ DESACTIVADA / PROBES ON ]\033[0m"
            print(f"  * {key:<20s} : {st}")
        
        print("\nOpciones de conmutacion:")
        print("  1. Alternar wordpress_shield")
        print("  2. Alternar exposure_shield")
        print("  3. Alternar framework_shield")
        print("  0. Volver")
        sub = input("Seleccione [0-3]: ").strip()
        key_map = {"1": "wordpress_shield", "2": "exposure_shield", "3": "framework_shield"}
        if sub in key_map:
            k = key_map[sub]
            self.islands[k] = not self.islands.get(k, True)
            if self.is_connected:
                self.api.update_islands_config(self.islands)
            print(f"\033[1;32m[OK] {k} conmutado a {self.islands[k]}.\033[0m\n")

    def _cli_simulator(self):
        print("\n\033[1;34m-- SIMULADOR DE VERIFICACION SAT EN VIVO --\033[0m")
        method = input("Metodo HTTP [GET]: ").strip().upper() or "GET"
        path = input("Ruta / URI Path [/api/v1/test]: ").strip() or "/api/v1/test"
        body = input("Cuerpo / Body (opcional): ").strip()

        if not self.is_connected:
            print("\033[1;33m[!] WAF Offline. Inicie el servidor para ejecutar verificaciones SAT.\033[0m\n")
            return

        ok, res = self.api.inspect_payload(method, path, "", body)
        if not ok:
            print(f"\033[1;31m[X] Error comunicando con el WAF: {res}\033[0m\n")
            return

        act = res.get("action", "ALLOW")
        cat = res.get("category", "BENIGN")
        lat = res.get("execution_time_us", 0.0)
        rules = res.get("matched_rules", [])

        if act == "BLOCK":
            print(f"\n\033[1;31m[DECISION] BLOCK [{cat}]\033[0m")
        else:
            print(f"\n\033[1;32m[DECISION] ALLOW [{cat}]\033[0m")

        print(f"Latencia SAT : \033[1;32m{lat:.2f} us\033[0m")
        r_str = ", ".join(r.get("rule_id", "") for r in rules) if rules else "Ninguna (Trafico Benigno)"
        print(f"Invariantes  : {r_str}")
        print(f"Prueba Causal: {res.get('causal_proof', 'N/A')}\n")


def main():
    parser = argparse.ArgumentParser(description="EXACTOR-RULES: Administrador TUI/CLI de Reglas e Islas WAF")
    parser.add_argument("--api", default=DEFAULT_API_URL, help=f"URL del Management API del WAF (por defecto: {DEFAULT_API_URL})")
    parser.add_argument("--config", default=None, help="Ruta al archivo waf_config.toml")
    parser.add_argument("--cli", action="store_true", help="Forzar modo consola de texto interactiva en vez de ncurses")
    args = parser.parse_args()

    app = ExactorRulesApp(api_url=args.api, config_path=args.config)

    if HAVE_CURSES and not args.cli:
        try:
            curses.wrapper(app.run_curses)
        except Exception as e:
            print(f"\n[EXACTOR-RULES] Error durante la ejecución del TUI: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        app.run_cli_fallback()

if __name__ == "__main__":
    main()
