# Modelo de Amenazas STRIDE - Laboratorio 3

**Caso de Estudio**: CrowdStrike Falcon Incident Automation Hub  
**Fecha de Actualización**: 2026-09-16  
**Autores**: Diego Andrade & Felipe Amador

---

## Matriz STRIDE

| ID | Categoría STRIDE | Hipótesis Técnica | Frontera de Confianza | Validación Red Team | Control Aplicado (Lab 3) | Estado / Remediación Futura |
|---|---|---|---|---|---|---|
| **H1** | **Information Disclosure** | El protocolo HTTP en claro permite a un observador en red capturar el contenido, inventario de activos (`public-inventory.txt`) y alertas de incidentes CrowdStrike en tránsito. | **TB-01** (Red -> Nginx) | Captura PCAP filtrada en Wireshark mostrando peticiones GET en texto plano. | **Aceptado / Mitigación Parcial**: Reducción del inventario público. | **Pendiente Lab 4**: Implementación de TLS/HTTPS y cifrado en tránsito. |
| **H2** | **Information Disclosure** | Las cabeceras HTTP y respuestas de error exponen información tecnológica precisa (`Server: nginx/1.18.0`) y rutas sensibles del sistema (`/.git/config`). | **TB-02** (Nginx -> App) | `curl -I` y escaneo pasivo OWASP ZAP identificando versión y falta de security headers. | **Corregido (Lab 3)**: Hardening de Nginx (`server_tokens off`, cabeceras `nosniff`, `DENY`, y denegación de rutas `/.`). | **Verificado**: En retest las cabeceras no muestran versión y `.git` responde 403 Forbidden. |
| **H3** | **Repudiation** | Sin correlación temporal adecuada entre los comandos del atacante y la telemetría del servidor, un usuario malévolo podría negar la ejecución de escaneos o peticiones. | **TB-01 / TB-02** | Comparación de timestamps UTC entre los comandos `nmap`/`curl` de Red Team y `access.log`. | **Corregido (Lab 3)**: Formato de log Nginx enriquecido con User-Agent, bytes y timestamps estandarizados UTC. | **Verificado**: Regla de detección Blue Team en Python/Bash correlaciona eventos por IP y ventana temporal. |
| **H4** | **Tampering** | Al carecer de autenticación e integridad en HTTP, un intermediario (MITM) podría alterar los payloads de respuesta o las alertas enviadas a `/api/v1/alerts/escalate`. | **TB-01** (Red -> Nginx) | Demostración de ausencia de TLS y firmas de integridad en los payloads JSON de la API. | **Demostrado sin Explotación Destructiva**: Identificación del riesgo sin realizar interceptación activa contra terceros. | **Pendiente Lab 4**: Autenticación mediante tokens JWT/OAuth2 y firmas de payload. |

---

## Resumen de Hipótesis Obligatorias del Laboratorio 3

1. **H1 (Information Disclosure - Tráfico en Claro)**: Demostrada mediante inspección de captura PCAP.
2. **H2 (Information Disclosure - Metadatos & Cabeceras)**: Remediada en la Fase E mediante Hardening de Nginx.
3. **H3 (Repudiation - Atribución de Eventos)**: Solventada mediante trazabilidad de logs Nginx y regla de detección.
4. **H4 (Tampering - Alteración de Tráfico)**: Documentada como riesgo aceptado en Lab 3 para corregirse con HTTPS/Identidad en Lab 4.
