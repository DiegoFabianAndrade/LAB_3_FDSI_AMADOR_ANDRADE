# Validación Dinámica con GDB ("Dynamic Verification & Debugging")

## 1. Propósito
Demostrar mediante la ejecución en tiempo real con **GDB (GNU Debugger)** la validación del flujo de ejecución de los binarios `crackme_level2` y `crackme_level2_stripped`, inspeccionando registros, memoria y puntos de interrupción (breakpoints).

---

## 2. Sesión GDB con Binario Simbólico (`crackme_level2`)

### Paso 1: Inicialización y Configuración
```bash
gdb ./crackme_level2
```
```gdb
(gdb) set disassembly-flavor intel
(gdb) break validate_key
Breakpoint 1 at 0x401162: file crackme_level2.c, line 10.
```

### Paso 2: Prueba de Caso Fallido (`AAAA`)
```gdb
(gdb) run AAAA
[Thread debugging using libthread_db enabled]

Breakpoint 1, validate_key (candidate=0x7fffffffe9ef "AAAA") at crackme_level2.c:10
(gdb) info registers rdi rax
rdi            0x7fffffffe9ef      140737488349679
rax            0x7fffffffe9ef      140737488349679
(gdb) continue
=== FDSI CrackMe Level 2 ===
Hint: static + dynamic analysis.
Invalid license.
[Inferior 1 (process 1091) exited with code 03]
```

**Análisis:**
- El registro `rdi` almacena el puntero al parámetro ingresado `"AAAA"`.
- Al evaluar `strlen("AAAA")` (4 bytes) contra `17` (`0x11`), el programa salta a la rutina de fallo y retorna `0` en `eax`.

### Paso 3: Inspección de Memoria en GDB
Inspección de las constantes de memoria en `.rodata`:

```gdb
(gdb) x/4xb 0x40208b
0x40208b <k.1>:	0x23	0x51	0x17	0x6a

(gdb) x/17xb 0x402090
0x402090 <expected.0>:	0x65	0x15	0x44	0x23	0x0e	0x03	0x52	0x3c
0x402098 <expected.0+8>:	0x66	0x03	0x44	0x2f	0x0e	0x63	0x27	0x58
0x4020a0 <expected.0+16>:	0x15
```

### Paso 4: Prueba de Caso Exitoso (`FDSI-REVERSE-2026`)
```gdb
(gdb) run FDSI-REVERSE-2026
[Thread debugging using libthread_db enabled]

Breakpoint 1, validate_key (candidate=0x7fffffffe9e2 "FDSI-REVERSE-2026") at crackme_level2.c:10
(gdb) info registers rdi rax
rdi            0x7fffffffe9e2      140737488349666
rax            0x7fffffffe9e2      140737488349666
(gdb) continue
=== FDSI CrackMe Level 2 ===
Hint: static + dynamic analysis.
License accepted.
FLAG{ghidra_plus_gdb}
[Inferior 1 (process 1130) exited normally]
```

**Análisis:**
- La clave `FDSI-REVERSE-2026` cumple la longitud de 17 bytes.
- En el bucle de acumulación XOR, `score` se mantiene en `0` (acumulado nulo en `or DWORD PTR [rbp-0x4], eax`).
- El valor de retorno en `eax` resulta en `1` (`sete al`), derivando en la llamada a `reveal_flag()`.

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
