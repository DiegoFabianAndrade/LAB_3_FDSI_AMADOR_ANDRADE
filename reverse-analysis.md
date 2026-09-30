# Informe de Ingeniería Inversa y Análisis de Binarios (Reverse CTF Lab)

## 1. Resumen Ejecutivo y Baseline Forense

Este informe documenta el análisis de ingeniería inversa estático y dinámico realizado sobre tres ejecutables Linux ELF x86-64 (`crackme_level1`, `crackme_level2`, `crackme_level2_stripped`) en el marco del **Reverse Engineering Challenge Lab**.

### Baseline Forense de Integridad

| Archivo | SHA-256 Hash | Arquitectura / Tipo | Estado de Símbolos |
|---|---|---|---|
| `crackme_level1` | `61e980febe84b1003b5a3b641468e915b984f7fdd835be9828af54233f88c68c` | ELF 64-bit LSB executable, x86-64, dynamically linked | Not Stripped (Debug Info) |
| `crackme_level2` | `8dc5931dfbf74d7371de9ca9ed8cc57bfe0af4521346202dcd1c701dd8b6f4e5` | ELF 64-bit LSB executable, x86-64, dynamically linked | Not Stripped (Debug Info) |
| `crackme_level2_stripped` | `c8e638741272a87ee3b30fe8878898c1aa977e6a879a1ec0b271034b5bb9aed3` | ELF 64-bit LSB executable, x86-64, dynamically linked | Stripped (No Symbols) |

---

## 2. Nivel 1 — Recon ("Strings Are Evidence")

### 2.1 Inspección y Formulación de Hipótesis
Mediante la ejecución de `strings -n 5 crackme_level1`, se identificó la constante de texto `REDTEAM-101` almacenada en claro en la sección de datos del binario. El desensamblado con `objdump -d -M intel crackme_level1` reveló una llamada directa a `strcmp` comparando el parámetro ingresado por el usuario (`argv[1]`) con dicha constante.

### 2.2 Validación y FLAG
- **Comando de Verificación:** `./crackme_level1 REDTEAM-101`
- **Contraseña:** `REDTEAM-101`
- **FLAG Nivel 1:** `FLAG{strings_are_evidence}`

---

## 3. Nivel 2 — Reverse Engineering & Decompilador Ghidra

### 3.1 Análisis de la Lógica de Validación
El análisis del binario `crackme_level2` desveló que la clave no se almacena en texto plano. La rutina `validate_key` realiza los siguientes pasos:
1. Comprueba que la longitud de la cadena sea de 17 caracteres (`0x11` en `strlen`).
2. Aplica una transformación XOR byte a byte combinando el carácter ingresado `candidate[i]` con un elemento del arreglo de máscara de 4 bytes `k = [0x23, 0x51, 0x17, 0x6a]` indexado por `i % 4`.
3. Compara el byte resultante con un arreglo esperado de 17 bytes en `.rodata`: `expected = [0x65, 0x15, 0x44, 0x23, 0x0e, 0x03, 0x52, 0x3c, 0x66, 0x03, 0x44, 0x2f, 0x0e, 0x63, 0x27, 0x58, 0x15]`.

### 3.2 Pseudocódigo Reconstruido

```c
int validate_key(const char *candidate) {
    if (strlen(candidate) != 17) return 0;
    
    const unsigned char k[4] = {0x23, 0x51, 0x17, 0x6a};
    const unsigned char expected[17] = {
        0x65, 0x15, 0x44, 0x23, 0x0e, 0x03, 0x52, 0x3c,
        0x66, 0x03, 0x44, 0x2f, 0x0e, 0x63, 0x27, 0x58, 0x15
    };
    
    int score = 0;
    for (size_t i = 0; i < 17; i++) {
        unsigned char transformed = candidate[i] ^ k[i % 4];
        score |= (expected[i] ^ transformed);
    }
    return (score == 0);
}
```

### 3.3 Reconstrucción y FLAG
Al aplicar la inversa XOR (`candidate[i] = expected[i] ^ k[i % 4]`), se obtuvo la clave:
- **Clave Válida:** `FDSI-REVERSE-2026`
- **Comando de Verificación:** `./crackme_level2 FDSI-REVERSE-2026`
- **FLAG Nivel 2:** `FLAG{ghidra_plus_gdb}`

---

## 4. Boss Level — Stripped Binary Analysis (`crackme_level2_stripped`)

### 4.1 Impacto de Stripping
Al remuever los símbolos con `strip`, desaparecen las entradas `.symtab` y `.strtab`. Herramientas como `nm` retornan `no symbols` y GDB no reconoce nombres de función como `validate_key` o `reveal_flag`.

### 4.2 Técnica de Análisis por Referencias y Offsets
- Se ubicó la función `main` rastreando la llamada desde `_start` a `__libc_start_main` (`0x401060` -> parámetro en `rdi` apunta a `main` en `0x4011d6`).
- Dentro de `main`, la llamada a `call 0x401156` ejecuta la rutina de validación.
- Al ejecutar `./crackme_level2_stripped FDSI-REVERSE-2026`, se confirmó la misma lógica y se obtuvo exitosamente la **FLAG**: `FLAG{ghidra_plus_gdb}`.

---

## 5. Módulo Comparativo: Burp Suite vs. Ghidra

| Característica | Ghidra / GDB / Binary Reverse | Burp Suite Community |
|---|---|---|
| **Capa de Análisis** | Código máquina / Ensamblador x86-64 / Memoria de procesos | Capa 7 (Aplicación / Protocolo HTTP/HTTPS) |
| **Objeto de Estudio** | Ejecutables compilados (ELF, PE, Mach-O) | Peticiones y respuestas HTTP en tránsito |
| **Herramientas Clave** | Decompilador, desensamblador, breakpoints, registros | Proxy interceptor, Repeater, Intruder, Decoder |
| **Propósito Principal** | Comprender la lógica interna, algoritmos y binarios sin código fuente | Analizar vulnerabilidades web (XSS, SQLi, CSRF, IDOR) |

---

## 6. Preguntas de Análisis Oficiales

### 1. ¿Qué información pudiste obtener sin ejecutar el binario?
Mediante inspección estática (`file`, `sha256sum`, `readelf`, `strings`, `objdump` / Ghidra) se obtuvieron los hashes de integridad, arquitectura x86-64, enlazado dinámico, símbolos de depuración, cadenas de texto embebidas y el grafo de flujo de control con las operaciones aritméticas XOR del algoritmo de validación.

### 2. ¿Por qué una contraseña compilada como string es un diseño inseguro?
Porque las cadenas de texto dentro de un binario no cifrado se almacenan directamente en la sección `.rodata` o `.data`, permitiendo que cualquier usuario o atacante las extraiga en texto plano en segundos con utilidades simples como `strings` o desensambladores, sin necesidad de ejecutar ni depurar el programa.

### 3. ¿Qué cambió entre `crackme_level2` y `crackme_level2_stripped`?
El proceso de *stripping* eliminó la tabla de símbolos y la información de depuración DWARF. Los nombres de variables (`candidate`, `expected`, `k`) y funciones (`validate_key`, `reveal_flag`) fueron removidos, forzando la navegación por direcciones absolutas de memoria (`0x401156`) y análisis de patrones de flujo en ensamblador.

### 4. ¿Qué ventaja tuvo Ghidra sobre `objdump`?
Ghidra ofrece decompilación avanzada a pseudocódigo de alto nivel similar a C, reconstrucción de estructuras de datos, grafo visual del flujo de control, análisis de referencias cruzadas (XREFs) y renombrado dinámico de variables, mientras que `objdump` solo ofrece el desensamblado plano en mnemónicos de ensamblador.

### 5. ¿Qué confirmó GDB que el análisis estático por sí solo no demostraba?
GDB confirmó en tiempo de ejecución los valores reales cargados en los registros de la CPU (`$rdi`, `$rax`), el recorrido exacto de los saltos condicionales (`je`, `jb`) ante entradas válidas e inválidas, y la respuesta del proceso en memoria en cada paso.

### 6. ¿Por qué Burp Suite no es una herramienta de ingeniería inversa de binarios?
Porque Burp Suite es un proxy de aplicación web diseñado para interceptar, modificar y analizar tráfico HTTP/HTTPS en la capa de red/aplicación, mientras que la ingeniería inversa de binarios analiza instrucciones binarias compiladas a nivel de procesador y memoria local.

### 7. ¿Qué controles de desarrollo evitarían embebidos inseguros de secretos en software real?
- Nunca almacenar secretos o claves criptográficas en el cliente.
- Implementar verificación de licencias basada en servidores remotos mediante HTTPS con autenticación asimétrica (firmas RSA/ECDSA o JWT).
- Aplicar *stripping* de símbolos y ofuscación de código en compilaciones de producción.
- Utilizar módulos de hardware seguro (HSM / TPM) o bóvedas de claves (Vault) para el manejo de secretos.

---

## 7. Guía de Sustentación en Vivo (3 Minutos por Equipo)

Para la presentación de 3 minutos ante el docente, siga este guión estructurado:

1. **Qué observamos inicialmente (0:00 - 0:40):**
   - Ejecutamos `file` y `sha256sum` en los binarios ELF x86-64. En el Nivel 1, con `strings` identificamos la clave `REDTEAM-101` y obtuvimos la `FLAG{strings_are_evidence}`.
2. **Qué hipótesis formulamos (0:40 - 1:15):**
   - En el Nivel 2, la clave ya no era visible en texto plano. Formulamos la hipótesis de que existía un bucle XOR que transformaba los bytes del input contra una clave repetitiva de 4 bytes.
3. **Qué función o condición encontramos (1:15 - 1:55):**
   - En Ghidra y `objdump` identificamos `validate_key()`, que exigía una longitud exacta de 17 bytes (`0x11`) y comparaba `candidate[i] ^ k[i % 4]` contra la matriz `expected`. Revertimos la operación XOR derivando la clave `FDSI-REVERSE-2026`.
4. **Cómo la confirmamos en ejecución (1:55 - 2:30):**
   - En GDB fijamos un breakpoint en `validate_key` (y por dirección `*0x401156` en la versión *stripped*). Confirmamos que con `AAAA` el programa retornaba `0` y fallaba, mientras que con `FDSI-REVERSE-2026` el registro `$rax` retornaba `1`, liberando la `FLAG{ghidra_plus_gdb}`.
5. **Qué enseñanza de desarrollo seguro obtenemos (2:30 - 3:00):**
   - Aprendimos que la ofuscación local o la verificación de secretos en binarios cliente es insegura (*Security by Obscurity*). Los secretos deben ser validados en servidores remotos autenticados mediante cifrado asimétrico.
