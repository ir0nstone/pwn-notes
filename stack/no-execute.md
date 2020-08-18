---
description: The defence against shellcode
---

# No eXecute

As you can expect, programmers were hardly pleased that people could inject their own instructions into the program. The NX bit, which stands for No eXecute, defines areas of memory as either **instructions** or **data**. This means that your input will be stored as **data**, and any attempt to run it as instructions will crash the program, effectively neutralising shellcode.

To get around NX, exploit developers have to leverage a technique called **ROP**, Return-Oriented Programming.

> The Windows version of NX is DEP, which stands for **D**ata **E**xecution **P**revention

