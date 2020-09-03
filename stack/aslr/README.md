---
description: Address Space Layout Randomisation
---

# ASLR

## Overview

ASLR stands for **A**ddress **S**pace **L**ayout **R**andomisation and can, in most cases, be thought of as `libc`'s equivalent of PIE - every time you run a binary, `libc` \(and other libraries\) get loaded into a different memory address.

{% hint style="danger" %}
While it's tempting to think of ASLR as `libc` PIE, there is a key difference.

ASLR is a **kernel protection** while PIE is a binary protection. The main difference is that PIE can be **compiled into the binary** while the presence of ASLR is **completely dependant on the environment running the binary**. If I sent you a binary compiled with ASLR disabled while I did it, it wouldn't make any different at all if you had ASLR enabled.
{% endhint %}

Of course, as with PIE, this means you cannot hardcode values such as function address \(e.g. `system` for a ret2libc\).

## The Format String Trap

It's tempting to think that, as with PIE, we can simply format string for a libc address and subtract a static offset from it. Sadly, we can't quite do that.

When functions finish execution, they do not get removed from memory; instead, they just get ignored and overwritten. Chances are very high that you will grab one of these remnants with the format string. Different libc versions can act very differently during execution, so a value you just grabbed may not even _exist_ remotely, and if it does the offset will most likely be different \(different libcs have different sizes and therefore different offsets between functions\). Naturally, it's possible to get lucky, but you shouldn't really hope that the offsets remain the same.

Instead, a more reliable way is reading the GOT entry of a specific function.

## Double-Checking

For the same reason as PIE, libc base addresses always end in the hexadecimal characters `000`.



