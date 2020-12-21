# Syscalls

### Overview

A **syscall** is a **sys**tem **call**, and is how the program enters the kernel in order to carry out specific tasks such as creating processes, I/O and any others they would require kernel-level access.

Browsing the [list of syscalls](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md), you may notice that certain syscalls are similar to libc functions such as `open()`, `fork()` or `read()`; this is because these functions are simply wrappers _around_ the syscalls, making it much easier for the programmer.

### Triggering Syscalls

On Linux, a syscall is triggered by the `int80` instruction. Once it's called, the kernel checks the value stored in RAX - this is the **syscall number**, which defines **what syscall gets run**. As per the table, the other parameters can be stored in RDI, RSI, RDX, etc and every parameter has a different meaning for the different syscalls.

### Execve

A notable syscall is the `execve` syscall, which executes the program passed to it in RDI. RSI and RDX hold `arvp` and `envp` respectively.

This means, if there is no `system()` function, we can use `execve` to call `/bin/sh` instead - all we have to do is pass in a pointer to `/bin/sh` to RDI, and populate RSI and RDX with `0` \(this is because both `argv` and `envp` need to be `NULL` to pop a shell\).

