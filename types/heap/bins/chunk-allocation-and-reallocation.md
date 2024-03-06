# Operations of the Unsorted Bin

When a non-fast chunk is freed, it gets put into the Unsorted Bin. When new chunks are requested, glibc looks at the unsorted bin.

* If the requested size is equal to the size of the chunk in the bin, return the chunk
* If it's smaller, split the chunk in the bin in two and return a portion of the correct size

TODO
