---
description: Bypassing NX
---

# Return-Oriented Programming

The basis of ROP is chaining together small chunks of code already present within the binary itself in such a way to do what you wish. This often involves passing parameters to functions already present within `libc`, such as `system` - if you can find the location of a command, such as `cat flag.txt`, and then pass it _as a parameter_ to `system`, it will execute that command and return the output. A more dangerous command is `/bin/sh`, which when run by `system` gives the attacker a shell much like the shellcode we used did.

Doing this, however, is not as simple as it may seem at first. To be able to properly call functions, we first have to understand how to pass parameters to them.

#### 



