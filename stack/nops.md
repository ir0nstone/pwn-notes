---
description: We can use NOPs for more reliable shellcode exploits
---

# NOPs

NOP \(no operation\) instructions do exactly what they sound like: _nothing_. Which makes then very useful for shellcode exploits, because all they will do is run the next instruction. If we pad our exploits on the left with NOPs and point EIP at the middle of them, it'll simply keep doing no instructions until it reaches our actual shellcode. This allows us a greater margin of error as a shift of a few bytes forward or backwards won't really affect it, it'll just run a different number of NOP instructions - which have the same end result of running the shellcode. This padding with NOPs is often called a NOP slide or NOP sled, since the EIP is essentially sliding down them.

In intel x86 assembly, NOP instructions are `\x90`.

### Updating our Shellcode Exploit

We can make slight changes to our exploit to do two things:

* Pad our shellcode from the left with NOPs
* Adjust our return pointer to point at the middle of the NOPs rather than the buffer start

> Make sure ASLR is still disabled. If you have to disable it again, you may have to readjust your previous exploit as the buffer location my be different.

```python

```

