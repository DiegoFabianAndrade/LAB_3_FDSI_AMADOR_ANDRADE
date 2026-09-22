# Registro de Riesgos y Estado de Controles - Laboratorio 3

**Caso de Estudio**: Portal de Activos MuVAutomation  
**Fecha de Evaluación**: 2026-09-22  
**Autores**: Diego Fabián Andrade Durán & Felipe Amador González  

---

## Tabla de Registro de Riesgos

| Riesgo ID | Amenaza / Descripción | Criterio STRIDE | Estado en Lab 3 | Control Aplicado / Mitigación | Tratamiento en Lab 4 |
|---|---|---|---|---|---|
| **RSK-01** | Fuga de versión de software (`Server: nginx/1.28.3`) | Information Disclosure (H2) | **Corregido** | Se configuró `server_tokens off;` en el bloque de servidor Nginx. El retest confirma que solo responde `Server: nginx`. | Control mantenido y reforzado. |
| **RSK-02** | Ausencia de cabeceras de seguridad HTTP (Clickjacking, MIME-Sniffing) | Information Disclosure / Tampering (H2/H4) | **Corregido** | Se agregaron las cabeceras `X-Content-Type-Options "nosniff"`, `X-Frame-Options "DENY"` y `Referrer-Policy "no-referrer"`. | Se mantendrán activas junto a cabeceras HSTS (`Strict-Transport-Security`). |
| **RSK-03** | Exposición de archivos de sistema ocultos (`.git/config`) | Information Disclosure (H2) | **Corregido** | Se añadió la directiva `location ~ /\. { deny all; }` denegando el acceso con un código HTTP 403 Forbidden. | Control mantenido. |
| **RSK-04** | Exposición de topología de activos en `public-inventory.txt` | Information Disclosure (H1/H2) | **Mitigado** | Reducción y anonimización de datos en el archivo de inventario, eliminando detalles internos innecesarios. | Se requerirá autenticación y control de acceso (RBAC). |
| **RSK-05** | Transmisión de peticiones y respuestas en texto plano (HTTP sin TLS) | Information Disclosure / Tampering (H1/H4) | **Aceptado (Límite Pedagógico)** | Riesgo documentado explícitamente y aceptado temporalmente para el alcance de la línea base del Laboratorio 3. | **Pendiente para Lab 4**: Implementación de TLS/HTTPS y certificados digitales. |
| **RSK-06** | Acceso no autenticado a recursos de administración | Spoofing / Tampering | **Aceptado (Límite Pedagógico)** | Permite probar el prototipo HTTP sin autenticación en la línea base del Laboratorio 3. | **Pendiente para Lab 4**: Implementación de identidad, sesiones y control de roles. |
