# LAB 3 - FDSI 2026: Aplicación Web Pública por HTTP
## CrowdStrike Incident Hub (Opción 1: Automatización de Incidentes)

### Integrantes
- **Felipe Amador González**
- **Diego Fabián Andrade Durán**

---

## 1. Descripción y Propósito

Este repositorio contiene la solución completa para el **Laboratorio 3: Aplicación web pública por HTTP (construir, atacar, detectar, corregir y verificar)**. 

El proyecto implementa un prototipo funcional de automatización de incidentes basado en la API de **CrowdStrike Falcon**, operando sobre HTTP sin autenticación según el alcance pedagógico del Laboratorio 3. Permite simular la recepción, clasificación, triaje y escalamiento de alertas ficticias, identificando los riesgos de seguridad asociados a la exposición de metadatos, tráfico sin cifrar y falta de cabeceras de protección.

---

## 2. Diagramas y Arquitectura

### Diagrama de Arquitectura
![Diagrama de Arquitectura](diagrams/diagrama%20de%20arquitectura.png)

### Diagrama de Flujo de Datos (DFD) y Fronteras de Confianza
Para consultar la descripción detallada de las 2 Fronteras de Confianza (**TB-01**: Red Externa -> Nginx; **TB-02**: Nginx -> App Backend), revise [architecture-dfd.md](diagrams/architecture-dfd.md).

![Diagrama de Flujo de Datos](diagrams/diagrama%20de%20flujo%20de%20datos.png)

---

## 3. Modelado de Amenazas (STRIDE)

La matriz completa de modelado de amenazas con las 4 hipótesis obligatorias (**H1-H4**) se encuentra en [stride-table.md](diagrams/stride-table.md).

---

## 4. Variables del Entorno del Laboratorio

```bash
export TARGET_IP=192.168.56.10
export TARGET_URL=http://192.168.56.10
export LAB_CIDR=192.168.56.0/24
date -u +%Y-%m-%dT%H:%M:%SZ
```

---

## 5. Guía de Ejecución y Reproducción

### 5.1 Iniciar el Prototipo de Automatización CrowdStrike Falcon

```bash
# Opción 1: Servidor Node.js Express
cd app
node server.js

# Opción 2: Servidor Estándar Python (Fallback sin dependencias externas)
python app/server.py
```

### 5.2 Nginx Hardening (Fase E)

```bash
# Aplicar configuración hardened
sudo cp nginx/muvautomation-after.conf /etc/nginx/sites-available/muvautomation
sudo nginx -t
sudo systemctl reload nginx
```

### 5.3 Probar la Regla de Detección Blue Team (Fase D)

```bash
python evidence/blue/detection_rule.py evidence/blue/access.log
```

---

## 6. Línea de Tiempo Purple Team

| Hora UTC | Rol | Acción Ejecutada | Evidencia Capturada | Conclusión & Correlación |
|---|---|---|---|---|
| **14:02:15** | Red Team | Escaneo Nmap de puerto 80 (`nmap -Pn -sV -p 80`) | [nmap_port80.nmap](evidence/red/nmap_port80.nmap) | Nmap identifica `nginx 1.18.0 (Ubuntu)` pero no genera entrada en `access.log` al no completar petición HTTP application layer. |
| **14:05:10** | Red Team | Reconocimiento con `curl -i "$TARGET_URL/"` | [curl_home.txt](evidence/red/curl_home.txt) | `access.log` registra `GET /` HTTP 200 con User-Agent `curl/7.88.1`. Fuga de versión confirmada. |
| **14:06:22** | Red Team | Consulta de metadatos `curl -I "$TARGET_URL/public-inventory.txt"` | [curl_headers.txt](evidence/red/curl_headers.txt) | `access.log` registra `HEAD /public-inventory.txt` HTTP 200. Ausencia de cabeceras de seguridad. |
| **14:10:15** | Red Team | Escaneo pasivo OWASP ZAP | [zap-passive-report.md](reports/zap-passive/zap-passive-report.md) | `access.log` registra accesos con User-Agent `OWASP ZAP 2.14.0`. Se detecta falta de `nosniff` y `DENY`. |
| **14:12:01** | Red Team | Enumeración de rutas en busca de archivos ocultos (`/.git/config`) | [access.log](evidence/blue/access.log) & [error.log](evidence/blue/error.log) | Ráfaga de respuestas 404. La regla de detección activa alerta por ráfaga de 404s (≥5 en 5 min). |
| **14:15:30** | Red Team | Consulta a API CrowdStrike Falcon (`POST /api/v1/alerts/postaggregates`) | [server.js](app/server.js) | Servidor procesa la agregación HTTP en texto claro y retorna agregados de alertas. |
| **16:00:00** | Blue/Purple | Aplicación de Hardening Nginx y Retest | [retest/headers_after.txt](evidence/retest/headers_after.txt) | Retest confirma que la versión de Nginx fue removida y `.git` retorna 403 Forbidden. |

---

## 7. Preguntas de Análisis

### 1. ¿Qué pudo observar el Red Team sin explotar ninguna vulnerabilidad?
El Red Team pudo identificar la versión exacta del servidor web (`Nginx 1.18.0 Ubuntu`), la estructura de rutas expuestas, la tecnología del prototipo y el inventario público de activos (`WEB-LAB-01`, `API-LAB-01`, `DB-LAB-01`), así como la ausencia total de cabeceras de seguridad HTTP (`X-Frame-Options`, `X-Content-Type-Options`) y la transmisión sin cifrado en la red.

### 2. ¿Qué pruebas de red no aparecieron en access.log y por qué?
El escaneo de puertos SYN (`nmap -Pn -sV -p 80`) no aparece en `access.log` porque Nginx solo registra peticiones de capa de aplicación (HTTP) que completen el handshake TCP y envíen una cabecera de solicitud HTTP válida. Los paquetes a nivel de capa de transporte (TCP/SYN) únicamente son visibles en la captura PCAP o en registros de firewall (`ufw.log`).

### 3. ¿Qué control aplicado reduce exposición, pero no resuelve el riesgo de HTTP?
La directiva `server_tokens off;` y las cabeceras de seguridad (`X-Content-Type-Options`, `X-Frame-Options`) reducen la exposición de información y previenen ataques como Clickjacking o MIME-sniffing; sin embargo, no resuelven la falta de confidencialidad e integridad inherente al protocolo HTTP, requiriendo TLS/HTTPS en el Laboratorio 4.

### 4. ¿Qué datos necesitaría Blue Team para distinguir curl legítimo de una actividad sospechosa?
Blue Team necesitaría telemetría adicional como la dirección IP de origen autenticada, correlación con la tasa de peticiones (burst rate), firmas de comportamiento (ja3/ja4 TLS fingerprints si aplicase), hashes del ejecutable cliente, encabezados HTTP adicionales (p. ej. X-Request-ID/JWT) y contexto de usuario/sesión.

### 5. ¿Qué amenaza STRIDE debe priorizarse en el Laboratorio 4?
Debe priorizarse **Spoofing** (Suplantación de Identidad) y **Tampering** (Alteración de Datos). Al implementar HTTPS (TLS), autenticación basada en identidades/roles y tokens JWT en el Lab 4, se mitigará la suplantación de clientes y la manipulación de cargas útiles en tránsito.

### 6. ¿Qué conclusión propuesta en el análisis defensivo no pudo comprobarse directamente?
La inferencia de que "un atacante externo ejecutó explotación activa de vulnerabilidades en la base de datos" no pudo comprobarse directamente, ya que la telemetría solo mostró enumeración HTTP sin payloads de explotación exitosa contra el backend.

---

## 8. Reflexión Individual (Máximo 250 palabras)

> El desarrollo del Laboratorio 3 permitió comprender de manera práctica la importancia de establecer una línea base de seguridad y evaluar los riesgos que emergen al exponer servicios por HTTP sin autenticación. A través de la emulación del prototipo de automatización de incidentes de CrowdStrike Falcon, se evidencia cómo la falta de cabeceras de seguridad y la exposición involuntaria de tokens de servidor facilitan la reconocimiento del Red Team sin requerir exploits complejos.
>
> Asimismo, la interacción entre Red Team y Blue Team demostró que la telemetría defensiva en Nginx (`access.log`) debe complementarse con reglas de correlación basadas en comportamiento (como la detección de ráfagas de 404s) y capturas de red en capa de transporte (PCAP) para obtener visibilidad completa. La aplicación de hardening básico demuestra cómo pequeñas correcciones de configuración reducen significativamente la superficie de ataque expuesta, preparando la infraestructura para la adición de controles de identidad y cifrado TLS en la siguiente fase del reto.

---

## 9. Registro de Riesgos

El estado de los riesgos mitigados, corregidos y pendientes para el Laboratorio 4 se encuentra en [risk-register.md](risk-register.md).
