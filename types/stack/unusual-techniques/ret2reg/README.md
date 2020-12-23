---
description: Using Registers to bypass ASLR
---

# ret2reg

**ret2reg** simply involves jumping to register addresses rather than hardcoded addresses, much like [Using RSP for Shellcode](../../reliable-shellcode/using-rsp.md). For example, you may find RAX _always_ points at your buffer when the `ret` is executed, so you could utilise a `call rax` or `jmp rax` to continue from there.

The reason RAX is the most common for this technique is that, by _convention_, the return value of a function is stored in RAX. For example, take the following basic code:

```c
#include <stdio.h>

int test() {
    return 0xdeadbeef;
}

int main() {
    test();
    return 0;
}
```

If we compile and disassemble the function, we get this:

```text
0x55ea94f68125      55             push rbp
0x55ea94f68126      4889e5         mov rbp, rsp
0x55ea94f68129      b8efbeadde     mov eax, 0xdeadbeef
0x55ea94f6812e      5d             pop rbp
0x55ea94f6812f      c3             ret
```

As you can see, the value `0xdeadbeef` is being moved into EAX.

