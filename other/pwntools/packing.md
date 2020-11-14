---
layout: post
tags: pwn
categories: pwntools
---

# Packing

Packing with the in-built python `struct` module is often a pain with loads of unnecessary options to remember. pwntools makes this a breeze, using the `context` global variable to automatically calculate how the packing should work.

## p64\(addr\)

Packs `addr` depending on `context`, which by default is **little-endian**.  


```python
p64(0x04030201) == b'\x01\x02\x03\x04'

context.endian = 'big'
p64(0x04030201) == b'\x04\x03\x02\x01'
```

{% hint style="info" %}
`p64()` returns a bytes-like object, so you'll have to form your padding as `b'A'` instead of just `'A'`.
{% endhint %}

## u64\(data\)

Unpacks `data` depending on `context`; exact opposite of `p64()`.

## flat\(\*args\)

Can take a bunch of arguments and packs them all according to `context`. The full functionality is quite [complex](http://docs.pwntools.com/en/stable/util/packing.html#pwnlib.util.packing.flat), but essentially:

```python
payload = flat(
    0x01020304,
    0x59549342,
    0x12186354
)
```

is equivalent to

```python
payload = p64(0x01020304) + p64(0x59549342) + p64(0x12186354)
```

{% hint style="danger" %}
`flat()` uses `context`, so unless you specify that it is 64 bits it will attempt to pack it as 32 bits.
{% endhint %}

