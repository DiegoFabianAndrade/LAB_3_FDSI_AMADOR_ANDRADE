# Modelo de Amenazas STRIDE - Laboratorio 3

**Caso de Estudio**: Portal de Activos MuVAutomation (Nginx sobre Ubuntu 24.04 LTS)  
**Fecha de Actualización**: 2026-09-16  
**Autores**: Diego Andrade & Felipe Amador

---

## Matriz STRIDE

| ID | Categoría STRIDE | Hipótesis Técnica | Frontera de Confianza | Validación Red Team | Control Aplicado (Lab 3) | Estado / Remediación Futura |
|---|---|---|---|---|---|---|
| **H1** | **Information Disclosure** | El protocolo HTTP en claro permite a un observador en red capturar el contenido del portal y el inventario público de activos (`public-inventory.txt`) en tránsito. | **TB-01** (Red -> Nginx) | Captura de paquetes en `tcpdump`/Wireshark mostrando peticiones GET en texto plano a `/public-inventory.txt`. | **Aceptado / Mitigación Parcial**: Reducción del contenido del inventario público. | **Pendiente Lab 4**: Implementación de TLS/HTTPS y cifrado en tránsito. |
| **H2** | **Information Disclosure** | Las cabeceras HTTP de Nginx exponen información tecnológica precisa (`Server: nginx/1.18.0 (Ubuntu)` o versión de SO) y respuestas por defecto en rutas no configuradas. | **TB-02** (Nginx -> Archivos Estáticos) | Consulta con `curl -I` identificando la fuga de versión y la falta de cabeceras de seguridad (`X-Frame-Options`, `X-Content-Type-Options`). | **Corregido (Lab 3)**: Hardening de Nginx (`server_tokens off`, cabeceras `nosniff`, `DENY`, y denegación de rutas sensibles `/.`). | **Verificado**: En retest las cabeceras no muestran la versión de Nginx y las rutas ocultas responden 403 Forbidden. |
| **H3** | **Repudiation** | Sin correlación adecuada de marcas de tiempo UTC e IP de origen en la telemetría del servidor, un usuario malévolo podría negar la ejecución de escaneos o peticiones HTTP. | **TB-01 / TB-02** | Comparación de timestamps UTC e IP entre las consultas del Red Team (`curl`/`nmap`) y los registros de `access.log`. | **Corregido (Lab 3)**: Registro estándar de accesos en `/var/log/nginx/access.log` asociando IP, fecha UTC, método HTTP y User-Agent. | **Verificado**: Trazabilidad completa de peticiones en los logs defensivos de Nginx en Ubuntu. |
| **H4** | **Tampering** | Al carecer de integridad y cifrado en HTTP, un intermediario (MITM) en el segmento de red podría alterar el código HTML de `index.html` o los datos de `public-inventory.txt`. | **TB-01** (Red -> Nginx) | Captura de red en `tcpdump`/Wireshark demostrando la transmisión sin firmas de integridad ni cifrado. | **Demostrado sin Explotación Destructiva**: Identificación del riesgo de manipulación de tráfico sin alterar la VM. | **Pendiente Lab 4**: Implementación de HTTPS (TLS) y validación de integridad en las respuestas. |

---

## Resumen de Hipótesis Obligatorias del Laboratorio 3

1. **H1 (Information Disclosure - Tráfico en Claro)**: Demostrada mediante inspección de captura de red `tcpdump`/Wireshark sobre `public-inventory.txt`.
2. **H2 (Information Disclosure - Metadatos & Cabeceras)**: Remediada en la Fase E mediante la aplicación de Hardening en Nginx (`server_tokens off`).
3. **H3 (Repudiation - Atribución de Eventos)**: Solventada mediante trazabilidad de peticiones y marcas de tiempo UTC en `/var/log/nginx/access.log`.
4. **H4 (Tampering - Alteración de Tráfico)**: Documentada como riesgo aceptado en Lab 3 para corregirse con HTTPS/Identidad en Lab 4.
