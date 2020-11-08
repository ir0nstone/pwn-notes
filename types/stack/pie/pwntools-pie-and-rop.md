# Pwntools, PIE and ROP

As shown in the [pwntools ELF tutorial](../../../other/pwntools/elf.md), pwntools has a host of functionality that allows you to really make your exploit dynamic. Simply setting `elf.address` will automatically update all the function and symbols addresses for you, meaning you don't have to worry about using `readelf` or other command line tools, but instead can receive it all dynamically.

Not to mention that the [ROP capabilities](https://ironstone.gitbook.io/notes/pwntools/rop) are incredibly powerful as well.

