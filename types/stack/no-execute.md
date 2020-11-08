---
description: The defence against shellcode
---

# No eXecute

As you can expect, programmers were hardly pleased that people could inject their own instructions into the program. The NX bit, which stands for No eXecute, defines areas of memory as either **instructions** or **data**. This means that your input will be stored as **data**, and any attempt to run it as instructions will crash the program, effectively neutralising shellcode.

To get around NX, exploit developers have to leverage a technique called **ROP**, Return-Oriented Programming.

{% hint style="info" %}
The Windows version of NX is DEP, which stands for **D**ata **E**xecution **P**revention
{% endhint %}

#### Checking for NX

You can either use pwntools' `checksec` or `rabin2`.

```text
$ checksec vuln
[*] 'vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

```text
$ rabin2 -I vuln
[...]
nx       false
[...]
```

