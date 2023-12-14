---
tags: pwn
categories: pwntools
---

# Logging and Context

## Logging

Logging is a very useful feature of pwntools that lets you know where in your code you've gotten up to, and you can log in different ways for different types of data.

### log.info(text)

```
>>> log.info('Binary Base is at 0x400000')
[*] Binary Base is at 0x400000
```

### log.success(text)

```
>>> log.success('ASLR bypassed! Libc base is at 0xf7653000')
[+] ASLR bypassed! Libc base is at 0xf7653000
```

### log.error(text)

```
>>> log.success('The payload is too long')
[-] The payload is too long
```

## Context

`context` is a 'global' variable in pwntools that allows you to set certain values once and all future functions automatically use that data.

```python
context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'
context.bits = 64
```

Now every time you generate shellcode or use the `p64()` and `u64()` functions it will be specifically designed to use the `context` variables, meaning it will _just work_. The power of pwntools.\
\


If you think that's a lot of setup, make it even simpler.

```python
context.binary = './vulnerable_binary'
```

This enables you to do a lot more things as well - for example, if you run

```python
p = process()
```

it will automatically use the `context` binary and you will not have to specify it again.
