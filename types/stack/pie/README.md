---
description: Position Independent Code
---

# PIE

## Overview

PIE stands for **Position Independent Executable**, which essentially means that every time you run the file it gets **loaded into a different memory address**. This means you cannot hardcode values such as function addresses and gadget locations without finding out where they are.

## Analysis

Luckily, this does _not_ mean it's impossible to exploit. PIE executables are based around **relative** rather than **absolute** addresses, meaning that while the locations in memory are fairly random the offsets between different **parts of the binary** remain **constant**. For example, if you know that the function `main` is located `0x128` bytes in memory after the base address of the binary, and you somehow find the location of `main`, you can simply subtract `0x128` from this to get the base address.

## Exploitation

So, all we need to do is find a _single_ address and PIE is bypassed. Where could we leak this address from?

The stack of course!

We know that the **return pointer** is located on the stack - and much like a canary, we can use format string \(or other ways\) to read the value off the stack. The value will always be a static offset away from the binary base, enabling us to completely bypass PIE!

## Double-Checking

Due to the way PIE randomisation works, the base address of a PIE executable will **always** end in the hexadecimal characters `000`. This is because **pages** are the things being randomised in memory, which have a standard size of `0x1000`. Operating Systems keep track of page tables which point to each section of memory and define the permissions for each section, similar to segmentation.

Checking the base address ends in `000` should _probably_ be the first thing you do if your exploit is not working as you expected.

