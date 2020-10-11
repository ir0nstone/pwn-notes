# Chunks

A "chunk" is a **region of the heap**. When the programmer uses `malloc()`, a chunk is returned. The [general structure of a chunk ](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html)is as follows:

```c
struct malloc_chunk {
  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

Also contained within the `mchunk_size` variable are the flags \(these 3 take up the last 3 bits, explaining why all chunk allocations are rounded to the nearest 8\):

* P \(PREV\_INUSE\)
  * `0` when the previous chunk in memory is free, meaning we can use `mchunk_prev_size` to calculate that chunk's size. If set, we cannot.
* M \(IS\_MMAPPED\)
  * Chunk is obtained using `mmap`, and these chunks are neither in an arena nor adjacent to a free chunk
* A \(NON\_MAIN\_ARENA\)
  * `0` if chunk is in main arena. Each spawned thread gains an arena and chunks there have this bit set.

This looks very intimidating, but there are two main things to bear in mind.

Firstly, the chunk is **not** just where your data gets stored. Every chunk contains **metadata** that describes the rest of the chunk, and its characteristics.

Secondly, the chunk has different behaviour depending on _whether it is free or not_. This is important to understand for some attacks.

Don't worry about the different variables - we'll cover what they are and their uses when they become relevant.

### Other Chunks

#### Top Chunk

Border the top of the arena. When `malloc` is called, it is used as a last resort; if more space is required, the chunk can grow using the `sbrk` system call. `PREV_INUSE` always set for this chunk.

#### Last Remainder Chunk

Sometimes you have no free chunks of an exact size, but rather just larger; this chunk **splits** into two to service the `malloc` request. One part is returned to the user with the desired size, the other becomes the **Last Remainder Chunk**.

