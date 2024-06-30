---
description: Supervisor Memory Access Protection
---

# SMAP

SMAP is a more powerful version of SMEP. Instead of preventing code in user space from being accessed, SMAP places **heavy** restrictions on accessing user space at all, even for accessing data. SMAP blocks the kernel from even _dereferencing_ (i.e. _accessing_) data that isn't in kernel space unless it is a set of very specific functions.

For example, functions such as `strcpy` or `memcpy` do not work for copying data to and from user space when SMAP is enabled. Instead, we are provided the functions `copy_from_user` and `copy_to_user`, which are allowed to briefly bypass SMAP for the duration of their operation. These functions also have additional hardening against attacks such as buffer overflows, with the function `__copy_overflow` acting as a guard against them.

This means that whether you interact using `write`/`read` or `ioctl`, the structs that you pass via pointers all get copied to kernel space using these functions before they are messed around with. This also means  that double-fetches are even more unlikely to occur as all operations are based on the snapshot of the data that the module took when `copy_from_user` was called (unless `copy_from_user` is called on the same struct multiple times).

Like SMEP, SMAP is controlled by the CR4 register, in this case the 21st bit. It is also [pinned](smep/kernel-rop-disabling-smep.md#failure), so overwriting CR4 does nothing, and instead we have to work around it.
