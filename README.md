# LAB 3 & LAB 4 - FDSI 2026: Secure Product Challenge & Reverse Engineering CTF

### Integrantes
- **Diego Fabián Andrade Durán**
- **Felipe Amador González**

---

## 📌 Visión General del Repositorio

Este repositorio contiene la solución técnica, telemetría, evidencias y código para los laboratorios de seguridad en desarrollo de software:

1. **Laboratorio 3: Aplicación Web Pública por HTTP (Red Team vs Blue Team)**: Despliegue de aplicación web sin autenticación, captura de tráfico en claro, hardening de Nginx, telemetría de logs y reglas de detección SIEM.
2. **Laboratorio 4 (Parte 2): Reverse Engineering Challenge CTF (Ingeniería Inversa de Binarios ELF x86-64)**: Análisis estático y dinámico sobre binarios compilados (`crackme_level1`, `crackme_level2`, `crackme_level2_stripped`) utilizando `file`, `sha256sum`, `strings`, `readelf`, `objdump`, `Ghidra` y `GDB`.

---

## 🛠️ Parte 1: Laboratorio 3 — Aplicación Web Pública por HTTP

### 1. Infraestructura y Despliegue
- **Servidor Web**: Nginx 1.28.3 sobre Ubuntu Linux (WSL2 / Windows local).
- **Directorio Raíz**: `/var/www/muvautomation/` (`index.html`, `public-inventory.txt`).
- **Configuración Hardened**: `/etc/nginx/sites-available/muvautomation` (`server_tokens off;`, cabeceras `nosniff`, `DENY`, `no-referrer`, `CSP`, `XSS-Protection`, denegación de rutas ocultas `/.`).

### 2. Evidencias de Red y Telemetría
- **Captura Wireshark**: [`evidence/blue/captura_wireshark_real.png`](evidence/blue/captura_wireshark_real.png) (secuencia TCP HTTP en claro `tcp.stream eq 14`).
- **Archivo PCAP**: [`evidence/blue/lab3-http.pcap`](evidence/blue/lab3-http.pcap).
- **Motor de Detección Python**: [`evidence/blue/detection_rule.py`](evidence/blue/detection_rule.py) (Resultado: `PASS`).

---

## 🧩 Parte 2: Laboratorio 4 — Reverse Engineering Challenge CTF

### 1. Resumen de Desafíos y FLAGS Obtenciadas

| Nivel | Ejecutable | Herramientas Utilizadas | Clave Descubierta | FLAG Obtenida |
|---|---|---|---|---|
| 🟢 **Nivel 1 (Recon)** | `crackme_level1` | `file`, `strings`, `objdump` | `REDTEAM-101` | `FLAG{strings_are_evidence}` |
| 🟡 **Nivel 2 (Reverse)** | `crackme_level2` | `readelf`, `Ghidra`, `GDB`, `Python` | `FDSI-REVERSE-2026` | `FLAG{ghidra_plus_gdb}` |
| 🔴 **Boss Level (Stripped)** | `crackme_level2_stripped` | `strings`, `objdump`, `GDB (*0x401156)` | `FDSI-REVERSE-2026` | `FLAG{ghidra_plus_gdb}` |

### 2. Baseline Forense de Integridad

```text
61e980febe84b1003b5a3b641468e915b984f7fdd835be9828af54233f88c68c  crackme_level1
8dc5931dfbf74d7371de9ca9ed8cc57bfe0af4521346202dcd1c701dd8b6f4e5  crackme_level2
c8e638741272a87ee3b30fe8878898c1aa977e6a879a1ec0b271034b5bb9aed3  crackme_level2_stripped
```

### 3. Comandos de Reproducción Rápida (WSL2 / Linux)

#### Nivel 1 (Recon)
```bash
chmod +x crackme_level1
strings -n 5 crackme_level1 | grep "REDTEAM"
./crackme_level1 REDTEAM-101
```

#### Nivel 2 (Reverse) & Boss Level
```bash
chmod +x crackme_level2 crackme_level2_stripped
./crackme_level2 FDSI-REVERSE-2026
./crackme_level2_stripped FDSI-REVERSE-2026
```

#### Verificación Dinámica en GDB
```bash
gdb ./crackme_level2
(gdb) set disassembly-flavor intel
(gdb) break validate_key
(gdb) run FDSI-REVERSE-2026
```

---

## 📁 Estructura del Repositorio y Documentación

```text
├── docs/
│   └── evidence/
│       └── reverse/
│           ├── baseline.txt
│           ├── level1.md
│           ├── level2.md
│           ├── gdb.md
│           └── screenshots/
├── reverse-analysis.md
├── README.md
├── comandos_evidencia.txt
├── risk-register.md
├── app/
│   ├── index.html
│   ├── public-inventory.txt
│   ├── server.js
│   ├── server.ps1
│   └── server.py
├── nginx/
│   ├── muvautomation-before.conf
│   └── muvautomation-after.conf
├── diagrams/
│   ├── architecture-dfd.md
│   ├── dfd-lab3.png
│   └── stride-table.md
├── evidence/
│   ├── red/
│   ├── blue/
│   └── retest/
└── reports/
    └── zap-passive/
```

- **Informe Detallado de Ingeniería Inversa**: [`reverse-analysis.md`](reverse-analysis.md)
- **Baseline Forense**: [`docs/evidence/reverse/baseline.txt`](docs/evidence/reverse/baseline.txt)
- **Documentación Nivel 1**: [`docs/evidence/reverse/level1.md`](docs/evidence/reverse/level1.md)
- **Documentación Nivel 2**: [`docs/evidence/reverse/level2.md`](docs/evidence/reverse/level2.md)
- **Depuración con GDB**: [`docs/evidence/reverse/gdb.md`](docs/evidence/reverse/gdb.md)

---

## 🎤 Guión de Sustentación en Vivo (3 Minutos)

1. **Qué observamos inicialmente (0:00 - 0:40):**
   - Registramos hashes SHA-256 e identificamos binarios ELF x86-64. En `crackme_level1`, `strings` expuso la clave `REDTEAM-101` y la `FLAG{strings_are_evidence}`.
2. **Qué hipótesis formulamos (0:40 - 1:15):**
   - En `crackme_level2`, la clave no estaba en texto plano. Formulamos la hipótesis de que se aplicaba una transformación XOR byte a byte con una máscara fija de 4 bytes (`k`).
3. **Qué función o condición encontramos (1:15 - 1:55):**
   - En Ghidra y `objdump` localizamos `validate_key()`, identificando la longitud de 17 bytes (`0x11`) y la comparación `candidate[i] ^ k[i % 4]` contra la matriz `expected`. Invertimos la operación obteniendo `FDSI-REVERSE-2026`.
4. **Cómo la confirmamos en ejecución (1:55 - 2:30):**
   - Con GDB pusimos breakpoints en `validate_key` (y offset `*0x401156` en la versión *stripped*). Confirmamos que con la clave candidata el registro de retorno `$rax` pasa a `1` y entrega la `FLAG{ghidra_plus_gdb}`.
5. **Enseñanza de Desarrollo Seguro (2:30 - 3:00):**
   - La verificación local o la ofuscación de secretos en binarios cliente es insegura. La validación de licencias debe realizarse en servidores remotos autenticados mediante cifrado asimétrico.
