# OWASP ZAP Reporte de Escaneo Pasivo - Laboratorio 3

**URL Objetivo**: `http://192.168.56.10/`  
**Fecha**: Wed, 16 Sep 2026 14:10:00 GMT  
**Modo de Escaneo**: Escaneo Pasivo (Sin cargas útiles destructivas)  

---

## Resumen de Observaciones Pasivas

| Alerta / Riesgo | Nivel de Riesgo | Fiabilidad | Descripción |
|---|---|---|---|
| **Exposición de Banner del Servidor** | Bajo / Info | Alta | La cabecera Server del HTTP filtra software y versión exacta (`Server: nginx/1.18.0 (Ubuntu)`). |
| **Ausencia de Cabecera X-Frame-Options** | Bajo | Alta | La protección contra Clickjacking está ausente en las respuestas HTTP. |
| **Ausencia de Cabecera X-Content-Type-Options** | Bajo | Alta | La prevención de MIME-sniffing (`nosniff`) está ausente. |
| **Ausencia de Cabecera Referrer-Policy** | Info | Alta | La política de Referrer está ausente, permitiendo fuga de rutas al navegar externamente. |
| **Transmisión HTTP en Claro** | Medio | Alta | La comunicación transita en puerto HTTP 80 sin cifrar. |

---

## Desglose Detallado de Alertamientos

### 1. Exposición de Versión del Servidor (STRIDE: H2 - Information Disclosure)
- **URL**: `http://192.168.56.10/`
- **Cabecera**: `Server: nginx/1.18.0 (Ubuntu)`
- **Impacto**: Permite identificar vulnerabilidades conocidas asociadas a la versión 1.18.0 de Nginx.
- **Remediación**: Configurar `server_tokens off;` en Nginx.

### 2. Ausencia de Cabeceras de Seguridad (STRIDE: H2 / H4)
- **Cabeceras Faltantes**: `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`
- **Remediación**: Añadir cabeceras en la configuración de Nginx.
