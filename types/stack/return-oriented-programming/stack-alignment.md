---
description: A minor issue
---

# Stack Alignment

A small issue you may get when pwning on 64-bit systems is that your exploit works perfectly locally but fails remotely - or even fails when you try to use the provided LIBC version rather than your local one. This arises due to something called **stack alignment**.

Essentially the [x86-64 ABI (application binary interface) guarantees 16-byte alignment on a `call` instruction](https://stackoverflow.com/questions/54393105/libcs-system-when-the-stack-pointer-is-not-16-padded-causes-segmentation-faul). LIBC takes advantage of this and uses [SSE data transfer instructions](https://docs.oracle.com/cd/E26502\_01/html/E28388/eojde.html) to optimise execution; `system` in particular utilises instructions such as `movaps`.

That means that if the stack is not 16-byte aligned - that is, RSP is not a multiple of 16 - the ROP chain will fail on `system`.

The fix is simple - in your ROP chain, before the call to `system`, place a singular `ret` gadget:

```python
ret = elf.address + 0x2439

[...]
rop.raw(POP_RDI)
rop.raw(0x4)        # first parameter
rop.raw(ret)        # align the stack
rop.raw(system)
```

This works because it will cause RSP to be popped an additional time, pushing it forward by 8 bytes and aligning it.
