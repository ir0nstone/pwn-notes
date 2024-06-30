---
description: Supervisor Memory Execute Protection
---

# SMEP

If [ret2usr ](../kernel-rop-ret2usr.md)is analogous to ret2shellcode, then SMEP is the new [NX](../../stack/no-execute.md). SMEP is a primitive protection that ensures [any code executed in kernel mode is located in kernel space](https://wiki.osdev.org/Supervisor\_Memory\_Protection). This means a simple ROP back to our own shellcode no longer works. To bypass SMEP, we have to use gadgets located in the kernel to achieve what we want to (without switching to userland code).

In older kernel versions we could [use ROP to disable SMEP entirely](kernel-rop-disabling-smep.md), but this has been patched out. This was possible because SMEP is determined by the [20th bit of the CR4 register](https://wiki.osdev.org/CPU\_Registers\_x86#CR4), meaning that if we can control CR4 we can disable SMEP from messing with our exploit.

We can enable SMEP in the kernel by controlling the respective QEMU flag (`qemu64` is not notable):

```
    -cpu qemu64,+smep
```

