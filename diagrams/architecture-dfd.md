# Arquitectura y Diagrama de Flujo de Datos (DFD) - Laboratorio 3

**Caso de Estudio**: Portal de Activos MuVAutomation  
**Entorno**: HTTP Público sin Autenticación (Línea Base de Seguridad)  

---

## 1. Diagrama de Arquitectura de Alto Nivel

```
 [ Red Team / Estación de Ataque ] (127.0.0.1 / Red Externa)
        │
        │ (Peticiones HTTP sin cifrar en puerto 80)
        ▼
  ╔════════════════════════════════════════════════════════════════════╗
  ║ TRUST BOUNDARY 1 (TB-01): Frontera Red / Host Servidor             ║
  ╚════════════════════════════════════════════════════════════════════╝
        │
        ▼
┌────────────────────────────────────────────────────────────────────┐
│ Ubuntu Host / WSL2 (127.0.0.1)                                     │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Nginx Web Server (Port 80)                                   │  │
│  │  - Sirve /index.html & /public-inventory.txt                 │  │
│  │  - Procesa cabeceras de respuesta y códigos de estado        │  │
│  └──────────────────────────────┬───────────────────────────────┘  │
│                                 │                                  │
│  ╔══════════════════════════════╧═══════════════════════════════╗  │
│  ║ TRUST BOUNDARY 2 (TB-02): Nginx Worker / Archivos del Host   ║  │
│  ╚══════════════════════════════╤═══════════════════════════════╝  │
│                                 │ (Acceso a Sistema de Archivos)   │
│                                 ▼                                  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Recursos Estáticos (/var/www/muvautomation/)                 │  │
│  │  - index.html (Portal de activos público)                    │  │
│  │  - public-inventory.txt (Demostración de inventario)         │  │
│  │  - Rutas bloqueadas (/.git/config denegado por regla Nginx)  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Telemetría Defensiva & Logs (Blue Team)                       │  │
│  │  - /var/log/nginx/access.log                                 │  │
│  │  - /var/log/nginx/error.log                                  │  │
│  │  - Captura PCAP (evidence/blue/lab3-http.pcap)               │  │
│  └──────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

---

## 2. Identificación de Fronteras de Confianza (Trust Boundaries)

### Frontera de Confianza 1 (TB-01): Red del Laboratorio / Host Ubuntu Nginx
- **Descripción**: Separa la red no confiable (donde opera el cliente o atacante) del servidor web expuesto.
- **Riesgos en Lab 3**: El puerto HTTP 80 está abierto sin TLS. Todo el tráfico transita en texto claro y no hay autenticación para limitar quién consulta el portal.
- **Mecanismos de Control**: Reglas de Firewall UFW restringidas al CIDR autorizado (`ufw allow 80/tcp`).

### Frontera de Confianza 2 (TB-02): Nginx Worker / Archivos Estáticos del Servidor
- **Descripción**: Separa el proceso del servidor web expuesto públicamente del sistema de archivos local (`/var/www/muvautomation/`).
- **Riesgos en Lab 3**: Si Nginx expone metadatos de cabecera (`Server: nginx/1.28.3`) o no restringe rutas sensibles (`/.git/config`), un atacante puede extraer información de versionamiento o archivos de configuración.
- **Mecanismos de Control**: Hardening de Nginx (`server_tokens off;`, cabeceras `nosniff`, `DENY`, `no-referrer`, y regla de bloqueo `location ~ /\. { deny all; }`).

---

## 3. Flujo de Datos Principal (Data Flow Diagram - DFD)

1. **Reconocimiento Inicial**: Atacante envía peticiones `SYN` y `GET` mediante `nmap` y `curl` hacia Nginx (TB-01).
2. **Servicio Estático**: Nginx responde con la página de inicio y expone `public-inventory.txt` (información de activos ficticios).
3. **Generación de Telemetría**: Nginx escribe la IP de origen, timestamp UTC, método HTTP, ruta y estatus en `access.log`.
4. **Inspección Defensiva**: Blue Team captura el tráfico en `lab3-http.pcap` y evalúa la regla de detección sobre `access.log`.
