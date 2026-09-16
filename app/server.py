#!/usr/bin/env python3
import http.server
import socketserver
import json
import time
from urllib.parse import urlparse

PORT = 8080

ALERTS_DB = [
    {
        "id": "inc_cs_9001",
        "timestamp": "2026-09-16T14:20:00Z",
        "composite_id": "det_falcon_881",
        "displayName": "Escaneo de puertos HTTP y reconocimiento de servicio",
        "severity": "High",
        "status": "new",
        "assigned_to": "unassigned",
        "agent_id": "WEB-LAB-01",
        "tactic": "Reconnaissance",
        "technique": "Active Scanning (T1595)",
        "description": "Múltiples peticiones HTTP 404 provenientes de un host explorando endpoints públicos."
    },
    {
        "id": "inc_cs_9002",
        "timestamp": "2026-09-16T14:35:12Z",
        "composite_id": "det_falcon_882",
        "displayName": "Acceso no cifrado a inventario público",
        "severity": "Medium",
        "status": "in_progress",
        "assigned_to": "soc_analyst_1",
        "agent_id": "API-LAB-01",
        "tactic": "Discovery",
        "technique": "Software Discovery (T1518)",
        "description": "Acceso a public-inventory.txt expone topología de activos a través de HTTP."
    }
]

ACTION_LOGS = []

class FalconHubHandler(http.server.BaseHTTPRequestHandler):
    def send_headers_custom(self, status=200, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Lab-Environment", "LAB3-HTTP-UNAUTHENTICATED")
        self.send_header("X-Falcon-Mock-Engine", "Active-Python")
        self.end_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path).path

        if parsed_path == "/":
            self.send_headers_custom(200, "text/html; charset=utf-8")
            html = """<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>MuvAutomation Lab - CrowdStrike Incident Hub (Python)</title>
  <style>
    body { font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }
    .card { background: #1e293b; border-radius: 8px; padding: 1.5rem; max-width: 800px; margin: auto; }
    h1 { color: #38bdf8; }
    a { color: #38bdf8; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Portal de Activos y CrowdStrike Falcon Hub [Python]</h1>
    <p>Entorno: LAB | Propietario: Blue Team</p>
    <ul>
      <li><a href="/public-inventory.txt">Inventario público de demostración</a></li>
      <li><a href="/api/v1/alerts">API de Alertas (JSON)</a></li>
      <li><a href="/api/v1/actions">Acciones de Triaje (JSON)</a></li>
    </ul>
  </div>
</body>
</html>"""
            self.wfile.write(html.encode("utf-8"))
            return

        if parsed_path == "/public-inventory.txt":
            self.send_headers_custom(200, "text/plain; charset=utf-8")
            txt = """=======================================================
MuvAutomation - Demostración de Inventario de Activos
=======================================================
ID-Activo     Nombre-Host     Segmento-IP   Rol
WEB-LAB-01    web.lab.local   192.168.56.10 Servidor Nginx / Incident Hub
API-LAB-01    api.lab.local   192.168.56.11 API CrowdStrike Falcon Mock
DB-LAB-01     db.lab.local    192.168.56.12 Base de Datos de Eventos
=======================================================
"""
            self.wfile.write(txt.encode("utf-8"))
            return

        if parsed_path == "/api/v1/alerts":
            self.send_headers_custom(200, "application/json")
            resp = {
                "meta": {
                    "total_alerts": len(ALERTS_DB),
                    "motor_triaje": "Procesador de Alertas CrowdStrike Falcon v1.0 [Python]"
                },
                "resources": ALERTS_DB
            }
            self.wfile.write(json.dumps(resp, indent=2).encode("utf-8"))
            return

        if parsed_path == "/api/v1/actions":
            self.send_headers_custom(200, "application/json")
            self.wfile.write(json.dumps({"actions": ACTION_LOGS}, indent=2).encode("utf-8"))
            return

        self.send_headers_custom(404, "application/json")
        self.wfile.write(json.dumps({"error": "404 Not Found"}).encode("utf-8"))

    def do_POST(self):
        parsed_path = urlparse(self.path).path
        content_length = int(self.headers.get('Content-Length', 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b'{}'
        
        try:
            payload = json.loads(body_bytes.decode('utf-8'))
        except Exception:
            payload = {}

        if parsed_path == "/api/v1/alerts/postaggregates":
            self.send_headers_custom(200, "application/json")
            resp = {
                "meta": {"status": 200},
                "resources": [
                    {"label": "Distribución por Severidad", "buckets": [{"count": len(ALERTS_DB), "value": "High/Medium"}]}
                ]
            }
            self.wfile.write(json.dumps(resp, indent=2).encode("utf-8"))
            return

        if parsed_path == "/api/v1/alerts/escalate":
            action_rec = {
                "action_id": f"act_{int(time.time())}",
                "alert_id": payload.get("alert_id", "inc_cs_9001"),
                "action_type": payload.get("action_type", "CONTAINMENT_RECOMMENDED"),
                "executed_by": "BlueTeam-SOAR-Bot",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            ACTION_LOGS.append(action_rec)
            self.send_headers_custom(201, "application/json")
            self.wfile.write(json.dumps({"status": "success", "action": action_rec}, indent=2).encode("utf-8"))
            return

        self.send_headers_custom(404, "application/json")
        self.wfile.write(json.dumps({"error": "404 Not Found"}).encode("utf-8"))

if __name__ == "__main__":
    print(f"Iniciando Servidor Falcon Hub Python en puerto {PORT}...")
    with socketserver.TCPServer(("", PORT), FalconHubHandler) as httpd:
        httpd.serve_forever()
