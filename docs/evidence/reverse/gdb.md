# Validación Dinámica con GDB ("Dynamic Verification & Debugging")

## 1. Propósito
Demostrar mediante la ejecución en tiempo real con **GDB (GNU Debugger)** la validación del flujo de ejecución de los binarios `crackme_level2` y `crackme_level2_stripped`, inspeccionando registros, memoria y puntos de interrupción (breakpoints).

---

### Evidencia Visual de la Sesión Dinámica en GDB
A continuación se presenta la captura de la sesión real interactiva en GDB ejecutada en Ubuntu WSL2 sobre `crackme_level2`:

![Sesión interactiva en GDB con punto de interrupción, inspección de registros y validación de casos](screenshots/12_gdb_dynamic_validation.png)

### Desglose y Análisis Técnico de la Sesión:

1. **Punto de Interrupción (`break validate_key`):**
   - Se estableció el breakpoint en la dirección `0x401162`, correspondiente al inicio del bloque de validación en `crackme_level2`.

2. **Caso Fallido (`run AAAA` → `Invalid license`):**
   - El ejecutable intercepta la llamada deteniendo la ejecución en `validate_key(candidate="AAAA")`.
   - **Registros `$rdi` y `$rax`:** El registro `$rdi` contiene el puntero al buffer del primer argumento (`0x7fffffffe08b` apuntando a `"AAAA"`).
   - **Evaluación:** La función calcula `strlen("AAAA") = 4`. Al compararlo con la longitud requerida de 17 caracteres (`0x11`), la condición falla inmediatamente.
   - **Resultado:** El acumulador de retorno `$eax` queda en `0`, imprimiendo `Invalid license.` y finalizando con código de salida `03`.

3. **Caso Exitoso (`run FDSI-REVERSE-2026` → `License accepted.`):**
   - Se reinicia el proceso con la clave calculada mediante la inversión XOR: `FDSI-REVERSE-2026`.
   - El breakpoint se activa en `validate_key(candidate="FDSI-REVERSE-2026")`.
   - **Registros `$rdi` y `$rax`:** El registro `$rdi` almacena el puntero en pila `0x7fffffffe07e` hacia la cadena válida.
   - **Evaluación:** La longitud es exactamente 17 bytes (`0x11`). El bucle XOR byte a byte procesa cada posición `i` contra `k[i % 4]` y `expected[i]`, resultando en diferencias nulas (`score = 0`).
   - **Resultado:** La instrucción `sete al` asigna `1` al registro de retorno `$rax`, activando la rama de éxito:
     - `License accepted.`
     - **FLAG Obtenida:** `FLAG{ghidra_plus_gdb}`
     - Proceso finalizado de forma normal (`exited normally`).

---

## 3. Sesión GDB con Binario Stripped (`crackme_level2_stripped`)

En el Boss Level, el ejecutable no contiene símbolos de función. Si intentamos `break validate_key`, GDB responde: `Function "validate_key" not defined.`

### Técnica de Depuración por Dirección Memoria / Offset:
1. Se identifica la dirección de memoria de la función de validación (`0x401156`) observando las llamadas en `main` (`call 0x401156`).
2. Se establece un punto de interrupción por dirección explicita: `break *0x401156`.

```gdb
(gdb) file ./crackme_level2_stripped
(gdb) set disassembly-flavor intel
(gdb) break *0x401156
Breakpoint 1 at 0x401156

(gdb) run FDSI-REVERSE-2026
Breakpoint 1, 0x0000000000401156 in ?? ()
(gdb) info registers rdi
rdi            0x7fffffffe9d9      140737488349657
(gdb) continue
=== FDSI CrackMe Level 2 ===
Hint: static + dynamic analysis.
License accepted.
FLAG{ghidra_plus_gdb}
[Inferior 1 (process 1251) exited normally]
```

---

## 4. Conclusión de la Verificación Dinámica
- La depuración dinámica en GDB permitió verificar experimentalmente los hallazgos del análisis estático.
- Se demostró que incluso en binarios *stripped* sin símbolos de depuración, la ejecución puede interceptarse y analizarse con precisión mediante direcciones absolutas de memoria e inspección de registros x86-64.
