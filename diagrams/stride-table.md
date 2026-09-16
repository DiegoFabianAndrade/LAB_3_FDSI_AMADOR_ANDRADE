# Tabla STRIDE - CrowdStrike Incident Hub

## Hipótesis de amenazas

| ID | STRIDE                  | Activo           | Hipótesis técnica                                                           | Validación                 |
|----|-------------------------|------------------|-----------------------------------------------------------------------------|----------------------------|
| H1 | Information Disclosure  | Alertas          | Las alertas pueden consultarse sin autenticación mediante HTTP.             | curl                       |
| H2 | Information Disclosure  | Tráfico HTTP     | Los datos viajan en texto plano.                                            | Wireshark                  |
| H3 | Repudiation             | Logs             | No existe identificación de usuarios.                                       | access.log                 |
| H4 | Tampering               | Datos en tránsito| HTTP no garantiza integridad.                                               | Verificación HTTP          |
| H5 | Spoofing                | Cliente HTTP     | Cualquier usuario puede hacerse pasar por un analista.                      | Acceso sin autenticación   |
