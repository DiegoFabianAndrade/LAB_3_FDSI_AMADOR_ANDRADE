# Modelo de Amenazas STRIDE - Laboratorio 3

**Caso de Estudio**: Portal de Activos MuVAutomation (Nginx en Ubuntu WSL2 / Linux)  
**Fecha de Actualización**: 2026-09-22  
**Autores**: Diego Fabián Andrade Durán & Felipe Amador González  

---

## 1. Matriz Integral STRIDE y Mapeo de Evidencias

| ID | Categoría STRIDE | Hipótesis Técnica | Frontera de Confianza | Comando Red Team (Ataque) | Evidencia Blue Team (Detección) | Control Aplicado (Hardening) | Comando y Resultado Retest | Estado en Risk Register |
|:---:|---|---|:---:|---|---|---|---|:---:|
| **H1** | **Information Disclosure** | El protocolo HTTP transmite tráfico sin cifrar en el puerto 80, permitiendo capturar en tránsito el contenido de `public-inventory.txt`. | **TB-01** (Red -> Nginx) | `curl -i "$TARGET_URL/public-inventory.txt"` | Archivo PCAP: [lab3-http.pcap](../evidence/blue/lab3-http.pcap)<br>Captura Wireshark: [captura_wireshark_real.png](../evidence/blue/captura_wireshark_real.png) | **Mitigación**: Reducción de datos sensibles en inventario.<br>*(Límite Pedagógico: TLS diferido para Lab 4)* | Inspección con filtro `http` en Wireshark (`tcp.stream eq 11`). Tráfico legible. | **Mitigado / Pendiente Lab 4** (RSK-04, RSK-05) |
| **H2** | **Information Disclosure** | Las cabeceras HTTP de Nginx exponen la versión exacta del software (`Server: nginx/1.28.3`), facilitando perfilado de exploits. | **TB-02** (Nginx -> Archivos) | `nmap -Pn -sV -p 80 "$TARGET_IP"`<br>`curl -I "$TARGET_URL/"` | Evidencia Red: [nmap_port80.nmap](../evidence/red/nmap_port80.nmap)<br>Reporte ZAP: [zap-passive-report.html](../reports/zap-passive/zap-passive-report.html) | Directiva `server_tokens off;` y cabeceras de seguridad (`nosniff`, `DENY`, `no-referrer`) en `nginx.conf`. | `curl -I "$TARGET_URL/"`<br>Resultado: [headers_after.txt](../evidence/retest/headers_after.txt) (`Server: nginx` sin versión). | **Corregido y Verificado** (RSK-01, RSK-02) |
| **H3** | **Repudiation** | Sin correlación de marcas de tiempo UTC, IP de origen y User-Agent en los registros, un actor malicioso puede negar escaneos o ráfagas HTTP. | **TB-01 / TB-02** | Ráfaga de reconocimiento:<br>`for p in /admin /.env /wp-config.php /backup.sql /.git/config; do curl -s -o /dev/null -w "%{http_code} $p\n" "$TARGET_URL$p"; done` | Logs: [access.log](../evidence/blue/access.log)<br>Journal: [journalctl_nginx.txt](../evidence/blue/journalctl_nginx.txt)<br>Regla: [detection_rule.py](../evidence/blue/detection_rule.py) | Formato estándar de `access.log` con `$remote_addr`, `$time_local`, `$request`, `$status`, `$http_user_agent` y script de detección. | `python3 evidence/blue/detection_rule.py evidence/blue/access.log`<br>Resultado: Alerta por ráfaga 404 y UA Nmap (Estado: PASS). | **Corregido y Verificado** (Trazabilidad Total) |
| **H4** | **Tampering** | La falta de integridad criptográfica en HTTP permite a un intermediario (MITM) alterar el HTML del portal o inyectar contenido sin que el cliente lo detecte. | **TB-01** (Red -> Nginx) | Demostración pasiva en Wireshark de ausencia de firmas o canal TLS sobre `index.html`. | Inspección de tramas TCP/HTTP en [lab3-http.pcap](../evidence/blue/lab3-http.pcap) demostrando texto plano sin verificación de integridad. | Documentación formal del vector de riesgo. *(Límite pedagógico: certificados e integridad diferidos para Lab 4)*. | Retest confirma persistencia de HTTP plano justificado por la línea base. | **Aceptado para Lab 4** (RSK-05, RSK-06) |

---

## 2. Guía para Sustentación ante el Docente (Paso a Paso en Tiempo Real)

Para sustentar la solución basándose estrictamente en STRIDE, siga este orden frente al profesor:

### Sustentación H1 — Information Disclosure (Tráfico en Claro)
1. **Qué explicar**: "Profesor, en H1 demostramos que HTTP transmite sin confidencialidad a través de la frontera TB-01."
2. **Cómo mostrar la evidencia en tiempo real**:
   * Abrir **Wireshark** con el archivo `evidence/blue/lab3-http.pcap`.
   * En la barra de filtros escribir: `http` (o `tcp.stream eq 11`).
   * Clic derecho en la petición `GET /public-inventory.txt` -> **Follow** -> **HTTP Stream**.
   * Mostrar que el texto del inventario (`WEB-LAB-01`, `API-LAB-01`, `DB-LAB-01`) es legible en texto plano.
   * Mostrar la captura guardada en [evidence/blue/captura_wireshark_real.png](../evidence/blue/captura_wireshark_real.png).
3. **Justificación de control**: "El riesgo fue mitigado reduciendo los metadatos expuestos, y queda formalmente aceptado en el Risk Register (RSK-05) para resolverse con HTTPS en el Laboratorio 4."

### Sustentación H2 — Information Disclosure (Fuga de Banners y Versiones)
1. **Qué explicar**: "En H2 evaluamos la fuga de información tecnológica en cabeceras HTTP antes y después del hardening."
2. **Cómo mostrar la evidencia en tiempo real**:
   * Mostrar el escaneo inicial en terminal o abriendo [evidence/red/nmap_port80.nmap](../evidence/red/nmap_port80.nmap):
     ```bash
     grep "nginx" evidence/red/nmap_port80.nmap
     # Muestra: 80/tcp open http nginx 1.28.3
     ```
   * Mostrar la respuesta antes del hardening en [evidence/red/curl_home.txt](../evidence/red/curl_home.txt) (`Server: nginx/1.28.3`).
   * Ejecutar el comando en vivo o mostrar el retest en [evidence/retest/headers_after.txt](../evidence/retest/headers_after.txt):
     ```bash
     curl -I http://127.0.0.1/
     ```
   * **Señalar al docente**: La versión `1.28.3` desapareció (ahora solo dice `Server: nginx`) y se agregaron las cabeceras `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` y `Referrer-Policy: no-referrer`.
   * Probar la denegación de rutas ocultas:
     ```bash
     curl -i http://127.0.0.1/.git/config
     ```
   * **Señalar al docente**: Retorna `HTTP/1.1 403 Forbidden` gracias a la regla `location ~ /\. { deny all; }`.

### Sustentación H3 — Repudiation (Trazabilidad y Detección de Eventos)
1. **Qué explicar**: "En H3 demostramos que el Blue Team cuenta con telemetría para correlacionar los ataques del Red Team e impedir el repudio de acciones."
2. **Cómo mostrar la evidencia en tiempo real**:
   * Mostrar las últimas líneas de [evidence/blue/access.log](../evidence/blue/access.log):
     ```bash
     tail -n 15 evidence/blue/access.log
     ```
   * Mostrar cómo cada petición tiene su timestamp UTC, IP origen (`127.0.0.1`), ruta y status code (`404` para escaneos, `403` para `.git`).
   * Ejecutar en vivo el motor de detección de incidentes:
     ```bash
     python3 evidence/blue/detection_rule.py evidence/blue/access.log
     ```
   * **Señalar al docente**: La salida marca `Estado: PASS`, identificando la ráfaga de 9 peticiones 404 en menos de 5 minutos y los User-Agents de escaneo (`Nmap Scripting Engine`).

### Sustentación H4 — Tampering (Integridad de Contenido)
1. **Qué explicar**: "En H4 documentamos que al carecer de TLS, un intermediario de red podría modificar el contenido en tránsito sin detección criptográfica. Este riesgo queda aceptado pedagógicamente en [risk-register.md](../risk-register.md) bajo el código RSK-05 para implementarse en el Laboratorio 4 mediante HTTPS, certificados y funciones hash de integridad."
