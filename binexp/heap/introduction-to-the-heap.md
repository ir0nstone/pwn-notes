# Introduction to the Heap

Unlike the stack, heap is an area of memory that can be dynamically allocated. This means that when you need new space, you can "request" more from the heap.

In C, this often means using functions such as `malloc()` to request the space. However, the heap is very slow and can take up tons of space. This means that the developer has to tell libc when the heap data is "finished with", and it does this via calls to `free()` which mark the area as available. But where there are humans there will be implementation flaws, and no amount of protection will ever ensure code is completely safe.

In the following sections, we will only discuss 64-bit systems (with the exception of some parts that were written long ago). The theory is the same, but pretty much any heap challenge (or real-world application) will be on 64-bit systems.
