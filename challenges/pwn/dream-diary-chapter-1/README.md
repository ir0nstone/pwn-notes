# Dream Diary: Chapter 1

## Overview

Dream Diary: Chapter 1 (known as **DD1**) was an `insane` pwn challenge. It is one of the few heap challenges on HackTheBox and, while it took a great deal of time to understand, was probably one of the most satisfying challenges I've done.

There were two (main) ways to solve this challenge: utilising an unlink exploit and overlapping chunks then performing a fastbin attack. I'll detail both of these, but first we'll identify the bug and what it allows us to do.

## Analysis

Let's have a look at what we can do.

```
ironstone@ubuntu:~/Desktop/hackthebox/chapter1$ ./chapter1 

+------------------------------+
|         Dream Diary          |
+------------------------------+
| [1] Allocate                 |
| [2] Edit                     |
| [3] Delete                   |
| [4] Exit                     |
+------------------------------+
>> 1

Size: 20
Data: ye
Success!
[...]
```

So at first look we can create, edit and delete chunks. Fairly standard heap challenge.

### Decompilation

Now we'll check out the binary in more detail.

{% hint style="info" %}
Many of the functions are bloated. If there is a chunk of irrelevant code, I'll just replace it with a comment that explains what it does (or in the case of canaries just remove altogether). I'll also remove convoluted multi-step code, so the types may be off, but it's much more readable.
{% endhint %}

#### Allocate

```c
/* Find free chunk index in the list */

/* Input size */

chunk = malloc(size);
*(void **)(&CHUNKLIST + (long)index * 8) = chunk; /* Add chunk address to list */

/* Check for Malloc Errors */

printf("Data: ");
read(*(void **)(&CHUNKLIST + index * 8), size);
puts("Success!");
```

Very simplified, but it takes in a size and then calls `malloc()` to assign a chunk of that size and reads that much data into the chunk.

#### Edit

```c
/* Input index */

/* check 0 <= index <= 15 */
/* Check if chunk address in list is zero - if it is, detect the UAF */

/* Read length of data stored there */
size = strlen(*(char **)(&CHUNKLIST + index * 8));
printf("Data: ");
read(*(void **)(&CHUNKLIST + index * 8), size);
puts("Done!");
```

Again, quite simplified. Calls `strlen()` on the data there, reads that many bytes in.

#### Delete

```c
/* Input index */

/* check 0 <= index <= 15 */
/* Check if chunk address in list is zero - if it is, detect the UAF */

free(*(void **)(&CHUNKLIST + index * 8));     /* Free the chunk */
*(&CHUNKLIST + index * 8) = 0; /* Zero out the entry - stop UAF and double-free */
puts("Done!");
```

### Finding the bug

The `delete()` function is secure, so it's clearly not an issue with the way the chunk is freed. Now we can check the functions that write data, `allocate()` and `edit()`.

`allocate()` only ever inputs how much it allocates, so it's secure. The bug is in `edit()`:

```c
size = strlen(*(char **)(&CHUNKLIST + index * 8));
read(*(void **)(&CHUNKLIST + index * 8), size);
```

Remember that `strlen()` stops at a **null byte**. If we completely fill up our buffer the first time we allocate, there are **no null bytes there**. Instead, we will continue into the `size` field of the next chunk.

![Chunk 1's data is right up against Chunk 2's size field](<../../../.gitbook/assets/image (30).png>)

Provided the `size` field is greater than `0x0` - which is will be - `strlen()` will interpret it as **part of the string**. That only gives us an overflow of one or two bytes.

But what can we do with that? The last 3 bits of the `size` field are taken up by the flags, the important one for this being the `prev_in_use` bit. If it is not set (i.e. `0`) then we can use `PREV_SIZE` to calculate the size of the previous chunk. If we overwrite `P` to be `0`, we can fake `PREV_SIZE` as it's [originally part of the previous chunk's data](https://ir0nstone.gitbook.io/notes/types/heap/chunks#allocated-chunks).

How we can utilise this will be detailed in the subpages.

## Scripting

Some helper functions to automate the actions.

```python
from pwn import *

elf = context.binary = ELF('./chapter1', checksec=False)
libc = elf.libc
p = process()

CHUNKLIST = 0x6020c0

def alloc(size=0x98, data='a'):
    p.sendlineafter('>> ', '1')
    p.sendlineafter('Size: ', str(size))
    p.sendlineafter('Data: ', data)

def free(idx=0):
    p.sendlineafter('>> ', '3')
    p.sendlineafter('Index: ', str(idx))

def edit(idx=0, data='a'):
    p.sendlineafter('>> ', '2')
    p.sendlineafter('Index: ', str(idx))
    p.sendlineafter('Data: ', data)
```
