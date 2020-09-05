---
description: The differences between the sizes
---

# 32- vs 64-bit

Everything we have done so far is applicable to 64-bit as well as 32-bit; the only thing you would need to change is switch out the `p32()` for `p64()` as the memory addresses are longer.

The real difference between the two, however, is the way you pass parameters to functions \(which we'll be looking at much closer soon\); in 32-bit, all parameters are pushed to the stack before the function is called. In 64-bit, however, the first 6 are stored in the registers RDI, RSI, RDX, RCX, R8 and R9 respectively as per the [calling convention](https://en.wikipedia.org/wiki/X86_calling_conventions). Note that different Operating Systems also have different calling conventions.

