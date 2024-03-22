# Safe Linking

Starting from **glibc 2.32**, a new **Safe-Linking** mechanism was implemented to protect the singly-linked lists (the fastbins and tcachebins). The theory is to **protect** the `fd` pointer of free chunks in these bins with a mangling operation, making it more difficult to overwrite it with an arbitrary value.

Every single `fd` pointer is protected by [the `PROTECT_PTR` macro](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L339), which is undone by [the `REVEAL_PTR` macro](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L341):

```c
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

Here, `pos` is the location of the current chunk and `ptr` the location of the chunk we are pointing to (which is NULL if the chunk is the last in the bin). Once again, we are using ASLR to protect! The `>>12` gets rid of the predictable last 12 bits of ASLR, keeping only the random upper 52 bits (or effectively 28, really, as the upper ones are pretty predictable):

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption><p>Image courtesy of <a href="https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/">https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/</a></p></figcaption></figure>

It's a very rudimentary protection - we use the current location and the location we point to in order to mangle it. From a programming standpoint, it has virtually no overhead or performance impact. We can see that `PROTECT_PTR` has been implemented in [`tcache_put()`](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L2941) and two locations in `_int_free()` (for fastbins) [here](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L4299) and [here](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L4310). You can find `REVEAL_PTR` used as well.

So, what does this mean to an attacker?

Again, **heap leaks are key**. If we get a heap leak, we know both parts of the XOR in `PROTECT_PTR`, and we can easily recreate it to fake our own mangled pointer.

***

It might be tempting to say that a partial overwrite is still possible, but there is a new security check that comes along with this Safe-Linking mechanism, the **alignment** check. This check ensures that chunks are 16-bit aligned and is only relevant to singly-linked lists (like all of Safe-Linking). A quick Ctrl-F for `unaligned` in [`malloc.c`](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c) will bring up plenty of different locations. The most important ones for us as attackers is probably the one in `tcache_get()` and the ones in `_int_malloc()`.

{% tabs %}
{% tab title="tcache_get" %}
When trying to get a chunk `e` **out** of the tcache, alignment is checked.

```c
if (__glibc_unlikely (!aligned_OK (e)))
  malloc_printerr ("malloc(): unaligned tcache chunk detected");
```
{% endtab %}

{% tab title="_int_malloc()" %}
There are three checks here. First on [`REMOVE_FB`](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L3587), the macro for removing a chunk from a fastbin:

```c
if (__glibc_unlikely (pp != NULL && misaligned_chunk (pp)))       \
    malloc_printerr ("malloc(): unaligned fastbin chunk detected");
```

Once on [the first chunk returned from the fastbin](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L3609):

```c
if (__glibc_unlikely (misaligned_chunk (victim)))
    malloc_printerr ("malloc(): unaligned fastbin chunk detected 2");
```

And lastly on every fastbin chunk during the [movement over to the respective tcache bin](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L3625):

```c
if (__glibc_unlikely (misaligned_chunk (tc_victim)))
    malloc_printerr ("malloc(): unaligned fastbin chunk detected 3");
```
{% endtab %}

{% tab title="_int_free()" %}
`_int_free()` checks the alignment if the `tcache_entry` [`key`](tcache-keys.md) is already set to the value it's meant to be and it has to do a whole double-free iteration check:

<pre class="language-c"><code class="lang-c">if (__glibc_unlikely (e->key == tcache))
{
    tcache_entry *tmp;
    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
    for (tmp = tcache->entries[tc_idx]; tmp; tmp = REVEAL_PTR (tmp->next))
    {
<strong>        if (__glibc_unlikely (!aligned_OK (tmp)))
</strong>            malloc_printerr ("free(): unaligned chunk detected in tcache 2");
        if (tmp == e)
            malloc_printerr ("free(): double free detected in tcache 2");
        /* If we get here, it was a coincidence.  We've wasted a
        few cycles, but don't abort.  */
    }
}
</code></pre>
{% endtab %}

{% tab title="malloc_consolidate()" %}
When all the fastbins are consolidated into the [unsorted bin](bins/chunk-allocation-and-reallocation.md), they are [checked for alignment](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L4508):

```c
if (__glibc_unlikely (misaligned_chunk (p)))
    malloc_printerr ("malloc_consolidate(): "
		     "unaligned fastbin chunk detected");
```
{% endtab %}

{% tab title="Others" %}
Not super important functions for attackers, but fastbin chunks are checked for alignment in [`int_mallinfo()`](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L4940), [`__malloc_info()`](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L5482), [`do_check_malloc_state()`](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L2173), [`tcache_thread_shutdown()`](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L2980).

```c
if (__glibc_unlikely (misaligned_chunk (p)))
    malloc_printerr ("<funcname>(): "
		     "unaligned fastbin chunk detected")
```

```c
if (__glibc_unlikely (!aligned_OK (e)))
    malloc_printerr ("tcache_thread_shutdown(): "
		     "unaligned tcache chunk detected");
```
{% endtab %}
{% endtabs %}

You may notice some of them use [`!aligned_OK`](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L1200) while others use [`misaligned_chunk()`](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L1202).

```c
#define aligned_OK(m)  (((unsigned long)(m) & MALLOC_ALIGN_MASK) == 0)

#define misaligned_chunk(p) \
  ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem (p)) \
   & MALLOC_ALIGN_MASK)
```

The macros are defined side-by-side, but really `aligned_OK` is for addresses while `misaligned_chunk` is for chunks.

[`MALLOC_ALIGN_MASK`](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc-internal.h#L62) is defined as such:

```c
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)
```

[`MALLOC_ALIGNMENT`](https://elixir.bootlin.com/glibc/glibc-2.32/source/sysdeps/i386/malloc-alignment.h#L22) is defined for i386 as `16`. In binary that's `10000`, so `MALLOC_ALIGN_MASK` is `1111`, so the final byte is checked. This results in 16-bit alignment, as expected.

This alignment check means you would have to guess 16 bits of entropy, leading to a 1/16 chance if you attempt to brute-force the last 16 bits to be&#x20;
