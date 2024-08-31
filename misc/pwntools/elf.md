---
layout: post
tags: pwn
categories: pwntools
---

# ELF

The pwntools `ELF` class is the most useful class you will probably ever need, so understanding the full power of it _will_ make your life easier. Essentially, the `ELF` class allows you to look up variables at runtime and stop hardcoding.

## Creating an ELF object

Creating an ELF object is very simple.

```python
elf = ELF('./vulnerable_program')
```

## Getting a process

Rather than specifying another process, we can just get it from the `ELF`:

```python
p = elf.process()
```

## The PLT and GOT

Want to do a `ret2plt`? Easy peasy.

```python
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
```

## Functions

Need to return to a function called `vuln`? Don't bother using a disassembler or debugger to find where it is.

```python
main_address = elf.functions['vuln']
```

Note that `elf.functions` returns a `Function` object, so if you only want the address you can use `elf.symbols`:

```python
main_address = elf.symbols['symbol']
```

## elf.libc

When local, we can grab the `libc` the binary is running with. Easy peasy.

```python
libc = elf.libc
```

## elf.search\(needle, writable=False\)

Search the entire binary for a specific sequence `needle` of characters. Very useful when trying to do a `ret2libc`. If `writable` is set it only checks for sections in memory that you can write to. Note this returns a **generator** so if you want the first match you have to enclose it in `next()`.

```python
binsh = next(libc.search(b'/bin/sh\x00'))
```

## elf.address

`elf.address` is the base address of the binary. If the binary does not have PIE enabled, then it's absolute; if it does, all addresses are relative \(they pretend the binary base is `0x0`\).

Setting the `address` value automatically updates the address of `symbols`, `got`, `plt` and `functions`, which makes it invaluable when adjusting for PIE or ASLR.

Let's say you leak the base address of `libc` while ASLR is enabled; with pwntools, it's ridiculously easy to get the location of `system` for a `ret2libc`.

```python
libc = elf.libc
libc.address = 0xf7f23000           # You 'leaked' this

system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh\x00'))
exit_addr = libc.symbols['exit']

# Now you can do the ret2libc
```

