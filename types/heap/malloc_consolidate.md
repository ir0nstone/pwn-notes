---
description: Consolidating fastbins
---

# malloc\_consolidate()

[Earlier](bins/operations-of-the-fastbin.md), I said that chunks that went to the unsorted bin would consolidate, but fastbins would not. This is _technically_ not true, but they don't consolidate automatically; in order for them to consolidate, the function [`malloc_consolidate()`](https://elixir.bootlin.com/glibc/glibc-2.29/source/malloc/malloc.c#L4448) has to be called. This function looks complicated, but it essentially just grabs all adjacent fastbin chunks and combines them into larger chunks, placing them in the unsorted bin.

Why do we care? Well, UAFs and the like are very _nice_ to have, but a Read-After-Free on a fastbin chunk can only ever leak you a heap address, as the singly-linked lists only use the `fd` pointer which points to another chunk (on the heap) or is NULL. We want to get a libc leak as well!

If we free enough adjacent fastbin chunks at once and trigger a call to `malloc_consolidate()`, they will consolidate to create a chunk that goes to the unsorted bin. The unsorted bin is doubly-linked, and acts accordingly - if it is the only element in the list, both `fd` and `bk` will point to a location in `malloc_state`,  which is contained within libc.

This means that the more important thing for us to know is _how_ we can trigger a largebin consolidation. By checking the calls to the function in [`malloc.c`](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c) (2.35), we can check.

{% hint style="info" %}
It's possible for earlier or later glibc versions to have a greater or lesser number of calls to a specific function, so make sure to check for your version! You may find another way exists.
{% endhint %}

{% tabs %}
{% tab title="_int_malloc" %}
The most common and most important trigger, a call to `malloc()` requesting a chunk of **largebin size** will [trigger a call to `malloc_consolidate()`](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3965).

```c
/*
   If this is a large request, consolidate fastbins before continuing [...]
 */

else
  {
    idx = largebin_index (nb);
    if (atomic_load_relaxed (&av->have_fastchunks))
      malloc_consolidate (av);
  }
```

This is especially useful because a huge `printf` format string can trigger a largebin request! This is because `printf` will allocate a buffer onder the hood, and if you use something like `%10000c` as a format string then a largebin will be allocated.

There is another call to it in the section [`use_top`](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4353). This section is called when the top chunk has to be used to service the request. The [first `if` condition](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4375) checks if the top chunk is large enough to service the request:

```c
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
{
    remainder_size = size - nb;
    remainder = chunk_at_offset (victim, nb);
    av->top = remainder;
    set_head (victim, nb | PREV_INUSE |
              (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head (remainder, remainder_size | PREV_INUSE);

    check_malloced_chunk (av, victim, nb);
    void *p = chunk2mem (victim);
    alloc_perturb (p, bytes);
    return p;
}
```

If not, [the next condition](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4392) checks if there are fastchunks in the arena. If there are, it calls `malloc_consolidate` to attempt to regain space to service the request!

```c
else if (atomic_load_relaxed (&av->have_fastchunks))
{
    malloc_consolidate (av);
    /* restore original bin index */
    if (in_smallbin_range (nb))
        idx = smallbin_index (nb);
    else
        idx = largebin_index (nb);
}
```

So, by filling the heap and requesting another chunk, we can trigger a call to `malloc_consolidate()`.

(If both conditions fail, `_int_malloc` falls back to esssentially using `mmap` to service the request).
{% endtab %}

{% tab title="_int_free" %}
TODO
{% endtab %}

{% tab title="malloc_trim" %}
Calling [`mtrim`](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L5038) will consolidate fastbins (which makes sense, given the name `malloc_trim`). Unlikely to ever be useful, but please do let me know if you find a use for it!
{% endtab %}

{% tab title="mallopt" %}
When changing malloc options using `mallopt`, [the fastbins are first consolidated](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L5450). This is pretty useless, as `mallopt` is likely called once (if at all) in the program prelude before it does anything.
{% endtab %}
{% endtabs %}
