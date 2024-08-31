---
description: Controlling registers when gadgets are lacking
---

# ret2csu

**ret2csu** is a technique for populating registers when there is a lack of gadgets. More information can be found in the [original paper](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf), but a summary is as follows:

When an application is dynamically compiled \(compiled with libc linked to it\), there is a selection of functions it contains to allow the linking. These functions contain **within them** a selection of gadgets that we can use to populate registers we lack gadgets for, most importantly `__libc_csu_init`, which contains the following two gadgets:

```text
0x004011a2      5b             pop rbx
0x004011a3      5d             pop rbp
0x004011a4      415c           pop r12
0x004011a6      415d           pop r13
0x004011a8      415e           pop r14
0x004011aa      415f           pop r15
0x004011ac      c3             ret
```

```text
0x00401188      4c89f2         mov rdx, r14                ; char **ubp_av
0x0040118b      4c89ee         mov rsi, r13                ; int argc
0x0040118e      4489e7         mov edi, r12d               ; func main
0x00401191      41ff14df       call qword [r15 + rbx*8]
```

The second might not **look** like a gadget, but if you look it calls `r15 + rbx*8`. The first gadget chain allows us to control both `r15` and `rbx` in that series of huge `pop` operations, meaning whe can control where the second gadget calls afterwards.

{% hint style="info" %}
Note it's `call qword [r15 + rbx*8]`, not `call qword r15 + rbx*8`. This means it'll calculate `r15 + rbx*8` then **go to that memory address**, read it, and call **that value**. This mean we have to find a memory address that contains where we want to jump.
{% endhint %}

These gadget chains allow us, despite an apparent lack of gadgets, to populate the RDX and RSI registers \(which are important for parameters\) via the second gadget, then jump wherever we wish by simply controlling `r15` and `rbx` to workable values.

This means we can potentially pull off syscalls for `execve`, or populate parameters for functions such as `write()`.

{% hint style="info" %}
You may wonder why we would do something like this if we're linked to libc - why not just read the GOT? Well, some functions - such as `write()` - require three parameters \(and at least 2\), so we would require ret2csu to populate them if there was a lack of gadgets.
{% endhint %}

