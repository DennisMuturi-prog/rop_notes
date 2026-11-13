# 🛡️ ROP & Binary Exploitation Cheat Sheet

A quick-reference guide and cheat sheet for binary analysis, ROP gadget hunting, stack pivoting, payload optimization, and `ret2_dlresolve` exploitation.

---

## 📑 Table of Contents

- [1. Gadget Hunting](#1-gadget-hunting)
- [2. Binary & Section Inspection](#2-binary--section-inspection)
- [3. Debugging & Pattern Generation](#3-debugging--pattern-generation)
- [4. Payload Engineering & Optimization](#4-payload-engineering--optimization)
- [5. Deep Dive: `ret2_dlresolve`](#5-deep-dive-ret2_dlresolve)

---

## 1. Gadget Hunting

| Task | Command | Description |
| :--- | :--- | :--- |
| **Search gadgets** | `ROPgadget --binary ./pivot32 \| grep -E "syscall"` | Search for syscall or specific instructions across the binary |
| **Deeper gadget depth** | `ROPgadget --binary ./fluff32 --depth 20 \| grep -E "pext"` | Increase instruction search depth to find complex gadgets |

> [!TIP]
> Use `--depth <N>` when common single/double-instruction gadgets aren't available. This searches up to `N` instructions prior to the `ret` opcode.

---

## 2. Binary & Section Inspection

### Viewing Segments & Disassembly

```bash
# View binary sections and permissions (radare2 suite)
rabin2 -S write432

# Dump contents of specific data sections (hex + ASCII)
objdump -s -j .rodata fluff

# Disassemble executable sections to inspect functions & gadgets
objdump -d vuln

# Disassemble the Procedure Linkage Table (.plt) in Intel syntax
objdump -d vuln -j .plt -M intel
```

### Searching for Useful Strings

```bash
# Search for strings with hexadecimal file offsets
strings -t x vuln | grep bin
```

- `-t x`: Prints the byte offset from the start of the file in hexadecimal format before each string (useful for locating `/bin/sh` or format strings).

---

## 3. Debugging & Pattern Generation

### Cyclic Patterns with Bad Character Filtering

When an input filter restricts certain bytes, generate de Bruijn patterns excluding those characters:

```bash
# Generate 500-byte cyclic pattern using only allowed characters (pwndbg / pwntools)
pwndbg> cyclic 500 -a "bcdefhijklmnopqrstuvwyz"

# Locate crash offset from register value / pattern fragment
cyclic -l 0x6262626e6262626d -a "bcdefhijklmnopqrstuvwyz"
```

### GDB Memory Inspection

```gdb
# Examine 4 words (4-byte units) in hexadecimal format at target address
x/4xw 0x0804A03C
```

Format breakdown: `x/[count][format][size]` (`4` units, `x` = hex, `w` = word / 4 bytes).

---

## 4. Payload Engineering & Optimization

### Payload Size Constraints

> [!WARNING]
> When your payload is larger than the available stack region or exceeds the `read()` buffer limit:
> 1. **Minimize payload size**: Reuse values already present in registers rather than writing full `pop` chains.
> 2. **Avoid newline corruption**: Use `p.send()` instead of `p.sendline()` in pwntools — `sendline()` appends `\n` (`0x0a`), which consumes an extra byte and might truncate or corrupt inputs.

### Stack Pivoting

If the initial stack buffer is too small to fit the full ROP chain:
- Pivot the stack pointer (`ESP` / `RSP`) to controlled memory (e.g., heap, `.bss`, or mmapped region).
- Execute a sequence of pivot gadgets, such as:
  ```nasm
  pop esp ; ret
  ```
  or:
  ```nasm
  mov esp, eax ; ret
  ```
  or:
  ```nasm
  leave ; ret      # mov esp, ebp ; pop ebp
  ```

### Function Chaining & Stack Cleanup

- **Argument Cleanup**: When chaining multiple standard calling-convention functions, clear stack arguments between calls using `pop_n_ret` gadgets (e.g., `pop esi; pop edi; ret` for two-argument functions).
- **Return to Main**: Prefer returning to `main` if the target function expects arguments setup by its caller, resetting the stack environment cleanly.
- **Staging Data**: Use `read(0, target_section, size)` to write arbitrary payloads or fake structures into writable binary sections (`.bss`, `.data`).

---

## 5. Deep Dive: `ret2_dlresolve`

`ret2_dlresolve` tricks the dynamic linker's runtime resolver (`_dl_runtime_resolve`) into resolving an arbitrary symbol (such as `system`) by passing a forged relocation entry and symbol structure in writable memory (`.bss`).

### Key Rules & Memory Alignment

> [!IMPORTANT]
> 1. **Structure Alignment**:
>    - Fake `Elf32_Rel` and `Elf32_Sym` addresses must align properly.
>    - The offset `(fake_reloc - JMPREL)` must be cleanly divisible by `sizeof(Elf32_Rel)` (8 bytes).
>    - The offset `(fake_sym - SYMTAB)` must be cleanly divisible by `sizeof(Elf32_Sym)` (16 bytes).
> 2. **`r_info` Calculation**:
>    - Set `r_info = (sym_index << 8) | 0x7`.
>    - The `0x7` corresponds to relocation type `R_386_JUMP_SLOT`.
>    - When `_dl_runtime_resolve` executes `r_info >> 8`, it extracts the exact `sym_index`.
> 3. **Hash Table & Boundary Avoidance**:
>    - Adjust your base address in `.bss` so `r_info.hash` lands on a zeroed/valid memory page to bypass version checks and assertion failures.

### Stack Layout for 32-bit `ret2_dlresolve`

```text
+------------------------------------+
|  PLT0 / dl_resolve default stub    |  <-- Resolves symbol dynamically
+------------------------------------+
|  reloc_arg                         |  <-- Offset relative to .rel.plt (JMPREL)
+------------------------------------+
|  Return address after system()     |  <-- e.g., exit() or main()
+------------------------------------+
|  Argument 1 (Pointer to "/bin/sh") |  <-- Argument passed to resolved function
+------------------------------------+
```
