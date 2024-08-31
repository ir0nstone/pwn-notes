---
description: New and efficient heap management
---

# The Tcache

Starting in [glibc 2.27](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c), a new heap feature called the **tcache** was released. The tcache was designed to be a performance booster, and the operation is very simple: every chunk size (up to size **0x410**) has its own **tcache bin**, which can store up to **7 chunks**. When a chunk of a specific size is allocated, the tcache bin is searched first. When it is freed, the chunk is added to the tcache bin; if it is full, it then goes to the standard fastbin/unsortedbin.

The tcache bin acts like a fastbin - it is a singly-linked list of free chunks of a specific size. The handling of the list, using `fd` pointers, is identical. As you can expect, the attacks on the tcache are also similar to the attacks on fastbins.

Ironically, years of defenses that were implemented into the fastbins - such as the [double-free protections](../double-free/double-free-protections.md) - were ignored in the initial implementation of the tcache. This means that using the heap to attack a binary running under glibc 2.27 binary is easier than one running under 2.25!
