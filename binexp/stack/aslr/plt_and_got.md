---
description: Bypassing ASLR
---

# PLT and GOT

The PLT and GOT are sections within an ELF file that deal with a large portion of the **dynamic linking**. Dynamically linked binaries are more common than statically linked binary in CTFs. The purpose of **dynamic linking** is that binaries do not have to carry all the code necessary to run within them - this reduces their size substantially. Instead, they rely on system libraries (especially `libc`, the C standard library) to provide the bulk of the fucntionality.\
For example, each ELF file will not carry their own version of `puts` compiled within it - it will instead dynamically link to the `puts` of the system it is on. As well as smaller binary sizes, this also means the user can continually upgrade their libraries, instead of having to redownload all the binaries every time a new version comes out.

#### So when it's on a new system, it replaces function calls with hardcoded addresses?

Not quite.

The problem with this approach is it requires `libc` to have a constant base address, i.e. be loaded in the same area of memory every time it's run, but remember that [_**ASLR**_](https://en.wikipedia.org/wiki/Address\_space\_layout\_randomization) exists. Hence the need for _dynamic_ linking. Due to the way ASLR works, these addresses need to be resolved _every time the binary is run_. Enter the PLT and GOT.

## The PLT and GOT

The PLT (**Procedure Linkage Table**) and GOT (**Global Offset Table**) work together to perform the linking.

When you call `puts()` in C and compile it as an ELF executable, it is not _actually_ `puts()` - instead, it gets compiled as `puts@plt`. Check it out in GDB:

![](../../../.gitbook/assets/puts\_plt.png)

Why does it do that?

Well, as we said, it doesn't know where `puts` actually is - so it jumps to the PLT entry of `puts` instead. From here, `puts@plt` does some very specific things:

* If there is a GOT entry for `puts`, it jumps to the address stored there.
* If there isn't a GOT entry, it will resolve it and jump there.

The GOT is a _massive_ table of addresses; these addresses are the actual locations in memory of the `libc` functions. `puts@got`, for example, will contain the address of `puts` in memory. When the PLT gets called, it reads the GOT address and redirects execution there. If the address is empty, it coordinates with the `ld.so` (also called the **dynamic linker/loader**) to get the function address and stores it in the GOT.

## How is this useful for binary exploitation?

Well, there are two key takeaways from the above explanation:

* Calling the PLT address of a function is equivalent to calling the function itself
* The GOT address contains addresses of functions in `libc`, and the GOT is within the binary.

The use of the first point is clear - if we have a PLT entry for a desirable `libc` function, for example `system`, we can just redirect execution to its PLT entry and it will be the equivalent of calling `system` directly; no need to jump into `libc`.

The second point is less obvious, but debatably even more important. As the GOT is part of the binary, it will always be a constant offset away from the base. Therefore, if PIE is disabled or you somehow leak the binary base, you know the exact address that contains a `libc` function's address. If you perhaps have an arbitrary read, it's trivial to leak the real address of the `libc` function and therefore bypass ASLR.

## Exploiting an Arbitrary Read

There are two main ways that I (personally) exploit an arbitrary read. Note that these approaches will cause not only the GOT entry to be return but _everything else until a null byte is reached_ as well, due to strings in C being null-terminated; make sure you only take the required number of bytes.

### ret2plt

A **ret2plt** is a common technique that involves calling `puts@plt` and passing the GOT entry of puts as a parameter. This causes `puts` to print out its own address in `libc`. You then set the return address to the function you are exploiting in order to call it again and enable you to

```python
# 32-bit ret2plt
payload = flat(
    b'A' * padding,
    elf.plt['puts'],
    elf.symbols['main'],
    elf.got['puts']
)

# 64-bit
payload = flat(
    b'A' * padding,
    POP_RDI,
    elf.got['puts']
    elf.plt['puts'],
    elf.symbols['main']
)
```

{% hint style="info" %}
`flat()` packs all the values you give it with `p32()` and `p64()` (depending on context) and concatenates them, meaning you don't have to write the packing functions out all the time
{% endhint %}

### %s format string

This has the same general theory but is useful when you have limited stack space or a ROP chain would alter the stack in such a way to complicate future payloads, for example when stack pivoting.

```python
payload = p32(elf.got['puts'])      # p64() if 64-bit
payload += b'|'
payload += b'%3$s'                  # The third parameter points at the start of the buffer


# this part is only relevant if you need to call the function again

payload = payload.ljust(40, b'A')   # 40 is the offset until you're overwriting the instruction pointer
payload += p32(elf.symbols['main'])

# Send it off...

p.recvuntil(b'|')                   # This is not required
puts_leak = u32(p.recv(4))          # 4 bytes because it's 32-bit
```

## Summary

* The PLT and GOT do the bulk of static linking
* The PLT resolves actual locations in `libc` of functions you use and stores them in the GOT
  * Next time that function is called, it jumps to the GOT and resumes execution there
* Calling `function@plt` is equivalent to calling the function itself
* An arbitrary read enables you to read the GOT and thus bypass ASLR by calculating `libc` base
