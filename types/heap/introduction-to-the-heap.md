# Introduction to the Heap

Unlike the stack, heap is an area of memory that can be dynamically allocated. This means that when you need new space, you can "request" more from the heap.

In C, this often means using functions such as `malloc()` to request the space. However, the heap is very slow and can take up tons of space. This means that the developer has to tell libc when the heap data is "finished with", and it does this via calls to `free()` which mark the area as available. But where there are humans there will be implementation flaws, and as you can expect, this approach can be broken.

