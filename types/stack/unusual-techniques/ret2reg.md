# ret2reg

**ret2reg** simply involves jumping to register addresses rather than hardcoded addresses, much like [Using RSP for Shellcode](../reliable-shellcode/using-rsp.md). For example, you may find RAX _always_ points at your buffer when the `ret` is executed, so you could utilise a `call rax` or `jmp rax` to continue from there.

TODO: binary

