---
description: Resolving our own libc functions
---

# ret2dlresolve

## Broad Overview

During a ret2dlresolve, the attacker tricks the binary into resolving a function of its choice \(such as `system`\) into the PLT. This then means the attacker can use the PLT function as if it was originally part of the binary, bypassing ASLR \(if present\) and requiring no libc leaks.

## Detailed Overview

Dynamically-linked ELF objects import `libc` functions when they are first called using the PLT and GOT. During the relocation of a runtime symbol, RIP will jump to the PLT and attempt to resolve the symbol. During this process a "resolver" is called.

{% hint style="info" %}
For all these screenshots, I broke at `read@plt`. I'm using GDB with the `pwndbg` plugin as it shows it a bit better.
{% endhint %}

![](../../../.gitbook/assets/image%20%2841%29.png)

The PLT jumps to wherever the GOT points. Originally, before the GOT is updated, it points back to the instruction after the `jmp` in the PLT to resolve it.

![](../../../.gitbook/assets/image%20%2835%29.png)

In order to resolve the functions, there are 3 structures that need to exist within the binary. Faking these 3 structures could enable us to trick the linker into resolving a function of our choice, and we can also pass parameters in \(such as `/bin/sh`\) once resolved.

## Structures

There are 3 structures we need to fake.

```text
$readelf -d source

Dynamic section at offset 0x2f14 contains 24 entries:
  Tag        Type                         Name/Value
 0x00000005 (STRTAB)                     0x804825c
 0x00000006 (SYMTAB)                     0x804820c
 0x00000017 (JMPREL)                     0x80482d8
 [...]
```

### JMPREL

The `JMPREL` segment \(`.rel.plt`\) stores the **Relocation Table**, which maps each entry to a symbol.

```text
$readelf -r source

Relocation section '.rel.dyn' at offset 0x2d0 contains 1 entry:
 Offset     Info    Type            Sym.Value  Sym. Name
0804bffc  00000206 R_386_GLOB_DAT    00000000   __gmon_start__

Relocation section '.rel.plt' at offset 0x2d8 contains 2 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804c00c  00000107 R_386_JUMP_SLOT   00000000   gets@GLIBC_2.0
0804c010  00000307 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
```

These entries are of type `Elf32_Rel`:

```c
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Word;
typedef struct
{
  Elf32_Addr    r_offset;               /* Address */
  Elf32_Word    r_info;                 /* Relocation type and symbol index */
} Elf32_Rel;
/* How to extract and insert information held in the r_info field.  */
#define ELF32_R_SYM(val)                ((val) >> 8)
#define ELF32_R_TYPE(val)               ((val) & 0xff)
```

The column `name` coresponds to our symbol name. The `offset` is the GOT entry for our symbol. `info` stores additional metadata.

Note the due to this the `R_SYM` of `gets` is `1` as `0x107 >> 8 = 1`.

### STRTAB

Much simpler - just a table of strings for the names.

![0x0804825c is the location of STRTAB we got earlier](../../../.gitbook/assets/image%20%2836%29.png)

### SYMTAB

Symbol information is stores here in an `Elf32_Sym` struct:

```c
typedef struct 
{ 
   Elf32_Word st_name ; /* Symbol name (string tbl index) */
   Elf32_Addr st_value ; /* Symbol value */ 
   Elf32_Word st_size ; /* Symbol size */ 
   unsigned char st_info ; /* Symbol type and binding */ 
   unsigned char st_other ; /* Symbol visibility under glibc>=2.2 */ 
   Elf32_Section st_shndx ; /* Section index */ 
} Elf32_Sym ;
```

The most important value here is `st_name` as this gives the **offset in STRTAB of the symbol name**. The other fields are not relevant to the exploit itself.

## Linking the Structures

We now know we can get the `STRTAB` offset of the symbol's string using the `R_SYM` value we got from the `JMPREL`, combined with `SYMTAB`:

![](../../../.gitbook/assets/image%20%2840%29.png)

Here we're reading `SYMTAB + R_SYM * size (16)`, and it appears that the offset \(the `SYMTAB` `st_name` variable\) is `0x10`.

![](../../../.gitbook/assets/image%20%2844%29.png)

And if we read that offset on `STRTAB`, we get the symbol's name!

## More on the PLT and GOT

Let's hop back to the GOT and PLT for a slightly more in-depth look.

![](../../../.gitbook/assets/image%20%2838%29.png)

If the GOT entry is unpopulated, we push the `reloc_offset` value and jump to the beginning of the `.plt` section. A few instructions later, the `dl-resolve()` function is called, with `reloc_offset` being one of the arguments. It then uses this `reloc_offset` to calculate the **relocation and symtab entries**.

## Resources

* [The Original Phrack Article](http://phrack.org/issues/58/4.html)
* [0ctf's babystack](https://gist.github.com/ricardo2197/8c7f6f5b8950ed6771c1cd3a116f7e62)
* [rk700 \(in Chinese\)](http://rk700.github.io/2015/08/09/return-to-dl-resolve/)

