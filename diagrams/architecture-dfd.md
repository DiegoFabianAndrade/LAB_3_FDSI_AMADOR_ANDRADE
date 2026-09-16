# Arquitectura y Diagrama de Flujo de Datos (DFD) - Laboratorio 3

**Caso de Estudio**: Opción 1 - Automatización de Incidentes de CrowdStrike Falcon  
**Entorno**: HTTP Público sin Autenticación (Línea Base de Seguridad)  

---

## 1. Diagrama de Arquitectura de Alto Nivel

```
[ Red Team / Kali Linux ] (192.168.56.20)
       │
       │ (Peticiones HTTP sin cifrar en puerto 80)
       ▼
 ╔════════════════════════════════════════════════════════════════════╗
 ║ TRUST BOUNDARY 1: Frontera Red Externa / Host Servidor            ║
 ╚════════════════════════════════════════════════════════════════════╝
       │
       ▼
┌────────────────────────────────────────────────────────────────────┐
│ Ubuntu Server LTS (Host Aplicación - 192.168.56.10)                 │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Nginx Reverse Proxy (Port 80)                                │  │
│  │  - Sirve /index.html & /public-inventory.txt                 │  │
│  │  - Redirige /api/* a Node.js/Python Backend                  │  │
│  └──────────────────────────────┬───────────────────────────────┘  │
│                                 │                                  │
│  ╔══════════════════════════════╧═══════════════════════════════╗  │
│  ║ TRUST BOUNDARY 2: Proxy Nginx / Proceso Interno Aplicación   ║  │
│  ╚══════════════════════════════╤═══════════════════════════════╝  │
│                                 │ (HTTP Loopback 127.0.0.1:8080)   │
│                                 ▼                                  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ CrowdStrike Incident Automation Hub (Node.js/Python App)     │  │
│  │  - GET  /api/v1/alerts (Consulta de Alertas Falcon)          │  │
│  │  - POST /api/v1/alerts/postaggregates (Agregados Falcon)     │  │
│  │  - POST /api/v1/alerts/escalate (Triaje & Respuesta SOAR)    │  │
│  │  - GET  /api/v1/actions (Registro de Acciones)              │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Telemetría Defensiva & Logs (Blue Team)                       │  │
│  │  - /var/log/nginx/access.log                                 │  │
│  │  - /var/log/nginx/error.log                                  │  │
│  │  - Capture PCAP (/tmp/lab3-http.pcap)                        │  │
│  └──────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

---

## 2. Identificación de Fronteras de Confianza (Trust Boundaries)

### Frontera de Confianza 1 (TB-01): Red del Laboratorio / Host Ubuntu Nginx
- **Descripción**: Separa la red no confiable (donde opera el Red Team / Kali Linux) del servidor web expuesto.
- **Riesgos en Lab 3**: El puerto HTTP 80 está abierto sin TLS. Todo el tráfico transita en texto claro y no hay autenticación para limitar quién consulta el portal o la API.
- **Mecanismos de Control**: Reglas de Firewall UFW restringidas al CIDR asignado (`sudo ufw allow from $LAB_CIDR to any port 80`).

### Frontera de Confianza 2 (TB-02): Nginx Proxy / Aplicación Backend CrowdStrike
- **Descripción**: Separa el proceso proxy Nginx expuesto públicamente del backend local (`127.0.0.1:8080`) que procesa y clasifica los incidentes ficticios de CrowdStrike Falcon.
- **Riesgos en Lab 3**: Si el proxy expone rutas sensibles (`/.git/config`) o metadatos de cabecera (`Server: nginx/1.18.0`), un atacante puede reconocer componentes internos o extraer el archivo de inventario público para priorizar objetivos.
- **Mecanismos de Control**: Hardening inicial de Nginx (`server_tokens off`, cabeceras de seguridad HTTP, bloqueo de archivos ocultos `location ~ /\. { deny all; }`).

---

## 3. Flujo de Datos Principal (Data Flow Diagram - DFD)

1. **Reconocimiento Inicial**: Atacante envía peticiones `SYN` y `GET` mediante `nmap` y `curl` hacia Nginx (TB-01).
2. **Servicio Estático**: Nginx responde con la página de inicio y expone `public-inventory.txt` (información de activos ficticios).
3. **Petición de API de Incidentes**: Atacante/Usuario consulta `POST /api/v1/alerts/postaggregates` para consultar la clasificación de alertas de CrowdStrike Falcon.
4. **Procesamiento de Triaje**: La aplicación Node.js/Python recibe la solicitud en `127.0.0.1:8080` (TB-02), procesa el agregador y retorna los datos en JSON.
5. **Generación de Telemetría**: Nginx escribe la IP de origen, timestamp UTC, método HTTP, ruta y estatus en `access.log`. Blue Team monitorea este log y ejecuta la regla de detección.
