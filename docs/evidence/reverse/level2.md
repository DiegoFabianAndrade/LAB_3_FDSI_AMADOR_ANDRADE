# Nivel 2 — Reverse Engineering con Ghidra ("Decompile & Reconstruct")

## 1. Descripción del Nivel
En el Nivel 2, el binario `crackme_level2` ya no almacena la clave de licencia en texto claro dentro de la sección de strings. La clave es validada mediante una función criptográfica reversible byte a byte (`XOR`). Se requiere ingeniería inversa estática (Ghidra / objdump) para reconstruir la lógica de validación y derivar la clave válida.

---

## 2. Análisis Estático y Desensamblado

### Paso 1: Exploración Inicial de Strings y Funciones
Se ejecutó `strings -n 5 crackme_level2` observando que la clave secreta ya no es visible. Sin embargo, la tabla de símbolos se conserva intacta:
- Función principal: `main`
- Rutina de validación: `validate_key`
- Rutina de éxito: `reveal_flag`

### Paso 2: Análisis del Flujo en `validate_key`
Se inspeccionó la función `validate_key` mediante desensamblado e importación en Ghidra, renombrando variables según la lógica deducida (`candidate`, `score`, `i`, `transformed`):

![Decompilación de validate_key en Ghidra con variables renombradas](screenshots/11_level2_ghidra_decompiler.png)

```assembly
0000000000401156 <validate_key>:
  40115a: sub    rsp,0x30
  40115e: mov    QWORD PTR [rbp-0x28],rdi    # candidato (string ingresado)
  401162: mov    QWORD PTR [rbp-0x18],0x11   # longitud esperada = 17 (0x11)
  40116e: mov    rdi,rax
  401171: call   strlen@plt
  401176: cmp    QWORD PTR [rbp-0x18],rax    # Verificar strlen(candidato) == 17
  40117a: je     401183
  40117c: mov    eax,0x0                     # Si longitud != 17, retorna 0 (Invalido)
```

**Conclusión Inicial:**
1. La clave de licencia debe tener exactamente **17 caracteres** (`0x11` en hexadecimal).

### Paso 3: Análisis del Bucle XOR
Dentro del bucle principal de `validate_key` (dirección `0x401194` a `0x4011e5`):

```assembly
  40119f: movzx  eax,BYTE PTR [rax]          # Leer candidato[i]
  4011a8: and    eax,0x3                     # i % 4 (índice en la clave XOR k)
  4011ae: lea    rax,[rip+0xed6]             # Dirección de k.1 = 0x40208b
  4011b5: movzx  eax,BYTE PTR [rdx+rax*1]    # k[i % 4]
  4011b9: xor    eax,ecx                     # candidato[i] ^ k[i % 4]
  4011bb: mov    BYTE PTR [rbp-0x19],al      # Guardar caracter transformado
  4011be: lea    rdx,[rip+0xecb]             # Dirección de expected.0 = 0x402090
  4011cc: movzx  eax,BYTE PTR [rax]          # expected[i]
  4011cf: xor    al,BYTE PTR [rbp-0x19]      # expected[i] ^ transformado
  4011d5: or     DWORD PTR [rbp-0x4],eax     # Acumular diferencias en score
```

---

## 3. Extracción de Datos de Memoria y Algoritmo

### Arreglos Extraídos de la Sección `.rodata`:
- **Arreglo de Máscara XOR (`k` a la dirección `0x40208b`, 4 bytes):**
  `k = [0x23, 0x51, 0x17, 0x6a]`
- **Arreglo Cifrado Esperado (`expected` a la dirección `0x402090`, 17 bytes):**
  `expected = [0x65, 0x15, 0x44, 0x23, 0x0e, 0x03, 0x52, 0x3c, 0x66, 0x03, 0x44, 0x2f, 0x0e, 0x63, 0x27, 0x58, 0x15]`

### Pseudocódigo Reconstruido (C):

```c
int validate_key(const char *candidate) {
    if (strlen(candidate) != 17) {
        return 0;
    }
    
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

### Derivación de la Clave Válida:
Dado que `(candidate[i] ^ k[i % 4]) ^ expected[i] == 0`, podemos revertir la propiedad conmutativa del operador XOR:
$$\text{candidate}[i] = \text{expected}[i] \oplus k[i \pmod 4]$$

Calculando byte a byte en Python:
- `0x65 ^ 0x23 = 0x46 ('F')`
- `0x15 ^ 0x51 = 0x44 ('D')`
- `0x44 ^ 0x17 = 0x53 ('S')`
- `0x23 ^ 0x6a = 0x49 ('I')`
- ...
- Clave resultante: **`FDSI-REVERSE-2026`**

---

## 4. Confirmación y Obtención de la FLAG

Se ejecutó el programa enviando la clave derivada:

```bash
./crackme_level2 FDSI-REVERSE-2026
```

**Resultado Obtenido:**
```text
=== FDSI CrackMe Level 2 ===
Hint: static + dynamic analysis.
License accepted.
FLAG{ghidra_plus_gdb}
```

- **Licencia Válida:** `FDSI-REVERSE-2026`
- **FLAG Nivel 2:** `FLAG{ghidra_plus_gdb}`

---

## 5. Lección de Desarrollo Seguro

1. **Inseguridad de Cifrados Triviales / Ofuscación Reversible (Security by Obscurity):**
   - El uso de operaciones XOR estáticas o máscaras fijas no constituye cifrado seguro. Cualquier algoritmo expuesto en un binario cliente puede ser desensamblado y revertido mediante decompiladores como Ghidra.
2. **Control Recomendado:**
   - La validación de licencias y autenticación crítica debe ser delegada a un servidor remoto autenticado mediante HTTPS y tokens firmados asimétricamente (JWT / RSA / ECDSA), donde la clave privada nunca reside en el cliente.
