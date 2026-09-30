# Nivel 1 — Recon ("Strings are Evidence")

## 1. Descripción del Nivel
El objetivo del Nivel 1 es analizar el binario `crackme_level1` mediante inspección estática básica sin acceso al código fuente para descubrir su mecanismo de autenticación y obtener la primera **FLAG**.

---

## 2. Metodología y Ejecución Paso a Paso

### Paso 1: Ejecución Inicial del Binario
Se ejecutó el programa sin parámetros y con un argumento arbitrario para observar su comportamiento en tiempo de ejecución:

```bash
chmod +x crackme_level1
./crackme_level1
./crackme_level1 prueba
```

**Salida Observada:**
```text
=== FDSI CrackMe Level 1 ===
Uso: ./crackme_level1 <password>
---
=== FDSI CrackMe Level 1 ===
Access denied.
```

### Paso 2: Análisis Estático con `strings`
Se inspeccionaron las cadenas imprimibles de 5 o más caracteres embebidas en la sección `.rodata` del ejecutable:

```bash
strings -n 5 crackme_level1
```

**Cadenas de Interés Identificadas:**
```text
REDTEAM-101
=== FDSI CrackMe Level 1 ===
Uso: %s <password>
Access granted.
Access denied.
strcmp
print_flag
```

**Formulación de Hipótesis:**
- La cadena `REDTEAM-101` aparece inmediatamente antes de los mensajes de interfaz y cerca del símbolo importado `strcmp`.
- Hipótesis: El programa compara directamente el primer argumento recibido por línea de comandos (`argv[1]`) con la cadena estática `REDTEAM-101` mediante la función de biblioteca estándar `strcmp`. Si coinciden, ejecuta la rutina `print_flag`.

### Paso 3: Desensamblado con `objdump`
Se confirmó la hipótesis mediante el análisis del desensamblado en sintaxis Intel:

```bash
objdump -d -M intel crackme_level1 | grep -A 20 "<main>:"
```

**Fragmento Relevante del Desensamblado:**
```assembly
0000000000401185 <main>:
  ...
  4011aa:  48 8b 45 c0        mov    rax,QWORD PTR [rbp-0x40] # argv
  4011ae:  48 83 c0 08        add    rax,0x8                  # argv[1]
  4011b2:  48 8b 00           mov    rax,QWORD PTR [rax]
  4011b5:  48 8d 15 50 0e 00  lea    rdx,[rip+0xe50]          # "REDTEAM-101"
  4011bc:  48 89 c7           mov    rdi,rax
  4011bf:  e8 8c fe ff ff     call   401050 <strcmp@plt>
  4011c4:  85 c0              test   eax,eax
  4011c6:  75 0e              jne    4011d6 <main+0x51>       # Si no es igual, salta a Access Denied
  4011c8:  e8 4a ff ff ff     call   401117 <print_flag>      # Si es igual, imprime FLAG
```

---

## 3. Confirmación y Obtención de la FLAG

Se probó la contraseña descubierta `REDTEAM-101`:

```bash
./crackme_level1 REDTEAM-101
```

**Resultado Obtenido:**
```text
=== FDSI CrackMe Level 1 ===
Access granted.
FLAG{strings_are_evidence}
```

- **Contraseña Correcta:** `REDTEAM-101`
- **FLAG Nivel 1:** `FLAG{strings_are_evidence}`

---

## 4. Lección de Desarrollo Seguro

1. **Inseguridad de Credenciales Embebidas (Hardcoded Secrets):**
   - Compilar secretos, claves de API, tokens o contraseñas en texto claro dentro de binarios es una vulnerabilidad crítica. Cualquier analista o atacante puede extraértelos en segundos utilizando herramientas triviales como `strings` o inspeccionando las secciones `.rodata` / `.data`.
2. **Control Recomendado:**
   - Nunca almacenar secretos en el código cliente o binario compilado.
   - Utilizar autenticación delegada por servidor, almacenamiento seguro en bóvedas de claves (Key Vaults) y derivados criptográficos con sal (salted hashes/PBKDF2/Argon2) para la verificación.
