# Bins

A bin is a \(doubly or singly linked\) list of free chunks. They are differentiated depending on the size of chunks within them. When a chunk is freed, it is "moved" to the bin \(note that this movement is **not physical**\).

### Fast Bins

There are 10 fast bins that contain chunks of the same size \(16, 24, 32, 40, 48, 56, 64, 72, 80 or 88 bytes\) **including metadata**.

Addition and deletion occur in a Last-In-First-Out \(LIFO\) manner.

### Unsorted Bin

There is only one of these. When small and large chunks are freed, they end of in this bin to speed up allocation and deallocation requests.

Essentially, this bin gives the chunks one last shot at being used. Future malloc requests, if smaller than the chunk currently in the bin, split up that chunk into two pieces and return one of them, speeding up the process. If the chunk requested is **larger**, then the chunks in this bin get moved to the respective Small/Large bins.

### Small Bins

There are 62 small bins of sizes 16, 24, ... , 504 bytes and, like fast bins, chunks of the same size are stored in the same bins. Small bins are **doubly-linked** and allocation and deallocation is FIFO.

Before ending up in the unsorted bin, contiguous small chunks \(small chunks next to each other in memory\) can **coalesce**, meaning their sizes combine and become a bigger chunk.

### Large Bins

63 large bins, can store chunks of different sizes. The free chunks are ordered in decreasing order of size, meaning insertions and deletions can occur at any point in the list.

The first 32 bins have a range of 64 bytes:

```text
1st bin: 512 - 568 bytes
2nd bin: 576 - 632 bytes
[...]
```

Like small chunks, large chunks can coalesce together before ending up in the unsorted bin.

### Head and Tail

Each bin is represented by two values, the `HEAD` and `TAIL`. As it sounds, `HEAD` is at the top and `TAIL` at the bottom. Most insertions happen at the `HEAD`, so in LIFO structures \(such as the fastbins\) reallocation occurs there too, whereas in FIFO structures \(such as small bins\) reallocation occurs at the `TAIL`. For fastbins, the `TAIL` is `null`.

