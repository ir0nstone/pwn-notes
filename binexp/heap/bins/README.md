# Freeing Chunks and the Bins

## An Overview of Freeing

When we are done with a chunk's data, the data is **freed** using a function such as `free()`. This tells glibc that we are done with this portion of memory.

In the interest of being as efficient as possible, glibc makes a lot of effort to **recycle** previously-used chunks for future requests in the program. As an example, let's say we need `100` bytes to store a string input by the user. Once we are finished with it, we tell glibc we are no longer going to use it. Later in the program, we have to input another 100-byte string from the user. Why not reuse that same part of memory? There's no reason not to, right?

It is the **bins** that are responsible for the bulk of this memory recycling. A bin is a (doubly- or singly-linked) list of free chunks. For efficiency, different bins are used for different sizes, and the operations will vary depending on the bins as well to keep high performance.

When a chunk is freed, it is "moved" to the bin. This movement is not physical, but rather a **pointer** - a **reference** to the chunk - is stored somewhere in the list.

## Bin Operations

There are four bins: **fastbins**, the **unsorted bin**, **smallbins** and **largebins**.

When a chunk is freed, the function that does the bulk of the work in glibc is [`_int_free()`](https://elixir.bootlin.com/glibc/glibc-2.3/source/malloc/malloc.c#L4102). I won't delve into the source code right now, but will provide hyperlinks to glibc 2.3, a very old one without security checks. You should have a go at familiarising yourself with what the code says, but bear in mind things have been moved about a bit to get to there they are in the present day! You can change the version on the left in **bootlin** to see how it's changed.

* First, [the `size` of the chunk is checked](https://elixir.bootlin.com/glibc/glibc-2.3/source/malloc/malloc.c#L4127). If it is less than the largest fastbin size, [add it to the correct fastbin](https://elixir.bootlin.com/glibc/glibc-2.3/source/malloc/malloc.c#L4139)
* Otherwise, if it's mmapped, [`munmap` the chunk](https://elixir.bootlin.com/glibc/glibc-2.3/source/malloc/malloc.c#L4237)
* Finally, [**consolidate them**](https://elixir.bootlin.com/glibc/glibc-2.3/source/malloc/malloc.c#L4165) and [put them into the unsorted bin](https://elixir.bootlin.com/glibc/glibc-2.3/source/malloc/malloc.c#L4172)

What is consolidation? We'll be looking into this more concretely later, but it's essentially the process of finding other free chunks around the chunk being freed and combining them into **one large chunk**. This makes the reuse process more efficient.

### Fastbins

Fastbins store small-sized chunks. There are 10 of these for chunks of size 16, 24, 32, 40, 48, 56, 64, 72, 80 or 88 bytes **including metadata**.

### Unsorted Bin

There is only one of these. When small and large chunks are freed, they end of in this bin to speed up allocation and deallocation requests.

Essentially, this bin gives the chunks one last shot at being used. Future malloc requests, if smaller than a chunk currently in the bin, split up that chunk into two pieces and return one of them, speeding up the process - this is the [Last Remainder Chunk](https://ir0nstone.gitbook.io/notes/types/heap/chunks#last-remainder-chunk). If the chunk requested is **larger**, then the chunks in this bin get moved to the respective Small/Large bins.

### Small Bins

There are 62 small bins of sizes 16, 24, ... , 504 bytes and, like fast bins, chunks of the same size are stored in the same bins. Small bins are **doubly-linked** and allocation and deallocation is FIFO.

The purpose of the `FD` and `BK` pointers as we saw before are to points to the chunks ahead and behind in the bin.

Before ending up in the unsorted bin, contiguous small chunks (small chunks next to each other in memory) can **coalesce (consolidate)**, meaning their sizes combine and become a bigger chunk.

### Large Bins

63 large bins, can store chunks of different sizes. The free chunks are ordered in decreasing order of size, meaning insertions and deletions can occur at any point in the list.

The first 32 bins have a range of 64 bytes:

```
1st bin: 512 - 568 bytes
2nd bin: 576 - 632 bytes
[...]
```

Like small chunks, large chunks can coalesce together before ending up in the unsorted bin.

## Head and Tail

Each bin is represented by two values, the `HEAD` and `TAIL`. As it sounds, `HEAD` is at the top and `TAIL` at the bottom. Most insertions happen at the `HEAD`, so in LIFO structures (such as the fastbins) reallocation occurs there too, whereas in FIFO structures (such as small bins) reallocation occurs at the `TAIL`. For fastbins, the `TAIL` is `null`.
