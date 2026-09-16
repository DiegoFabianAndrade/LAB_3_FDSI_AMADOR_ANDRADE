#!/usr/bin/env python3
import sys
import re
from datetime import datetime
from collections import defaultdict

LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else "evidence/blue/access.log"
WINDOW_SECONDS = 300
THRESHOLD_404 = 5

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]+" (?P<status>\d+) (?P<bytes>\d+) "[^"]*" "(?P<ua>[^"]*)"'
)

def parse_nginx_time(time_str):
    clean_str = time_str.split(' ')[0]
    return datetime.strptime(clean_str, "%d/%b/%Y:%H:%M:%S")

def run_detection():
    print("=======================================================================")
    print("[MOTOR-DETECCION] Evaluación de Reglas de Seguridad Iniciada")
    print(f"Archivo de Log: {LOG_FILE}")
    print("=======================================================================")

    ip_404_timestamps = defaultdict(list)
    recon_ua_alerts = []

    suspicious_ua_patterns = ['nmap', 'zap', 'nikto', 'sqlmap']

    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                match = LOG_PATTERN.match(line.strip())
                if not match:
                    continue

                ip = match.group('ip')
                time_obj = parse_nginx_time(match.group('time'))
                status = int(match.group('status'))
                path = match.group('path')
                user_agent = match.group('ua')

                ua_lower = user_agent.lower()
                for kw in suspicious_ua_patterns:
                    if kw in ua_lower:
                        recon_ua_alerts.append({
                            "line": line_no,
                            "ip": ip,
                            "timestamp": time_obj.isoformat(),
                            "user_agent": user_agent,
                            "path": path
                        })

                if status == 404:
                    ip_404_timestamps[ip].append((time_obj, path))

    except FileNotFoundError:
        print(f"[ERROR] No se pudo abrir el archivo de log: {LOG_FILE}")
        return

    burst_alerts = []
    for ip, events in ip_404_timestamps.items():
        events.sort(key=lambda x: x[0])
        for i in range(len(events)):
            window = [e for e in events if 0 <= (e[0] - events[i][0]).total_seconds() <= WINDOW_SECONDS]
            if len(window) >= THRESHOLD_404:
                burst_alerts.append({
                    "ip": ip,
                    "count": len(window),
                    "start_time": window[0][0].isoformat(),
                    "end_time": window[-1][0].isoformat(),
                    "paths": [e[1] for e in window]
                })
                break

    print(f"\n[RESUMEN] Alertas de User-Agent de Reconocimiento: {len(recon_ua_alerts)}")
    for alert in recon_ua_alerts:
        print(f"  [ALERTA-UA] IP: {alert['ip']} | Ruta: {alert['path']} | Agente: {alert['user_agent']}")

    print(f"\n[RESUMEN] Alertas de Ráfaga HTTP 404 Detectadas: {len(burst_alerts)}")
    for alert in burst_alerts:
        print(f"  [ALERTA-RAFAGA] IP: {alert['ip']} generó {alert['count']} errores 404 entre {alert['start_time']} y {alert['end_time']}")
        print(f"    Rutas objetivo: {', '.join(alert['paths'])}")

    print("\n=======================================================================")
    print("[MOTOR-DETECCION] Evaluación de Reglas Completada - Estado: PASS")
    print("=======================================================================")

if __name__ == "__main__":
    run_detection()
