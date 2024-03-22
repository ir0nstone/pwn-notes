---
description: A primitive double-free protection
---

# Tcache Keys

Starting from glibc 2.29, the tcache was hardened by the addition of a second field in the `tcache_entry` struct, the [`key`](https://elixir.bootlin.com/glibc/glibc-2.29/source/malloc/malloc.c#L2908):

```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;
```

It's a pointer to a `tcache_perthread_struct`. In the [`tcache_put()`](https://elixir.bootlin.com/glibc/glibc-2.29/source/malloc/malloc.c#L2928) function, we can see what `key` is set to:

```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

When a chunk is freed and `tcache_put()` is called on it, the `key` field is set to the location of the `tcache_perthread_struct`. Why is this relevant? Let's check [the tcache security checks in `_int_free()`](https://elixir.bootlin.com/glibc/glibc-2.29/source/malloc/malloc.c#L4189):

```c
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
	/* Check to see if it's already in the tcache.  */
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache))
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)
		malloc_printerr ("free(): double free detected in tcache 2");
	    /* If we get here, it was a coincidence.  We've wasted a
	       few cycles, but don't abort.  */
	  }

	if (tcache->counts[tc_idx] < mp_.tcache_count)
	  {
	    tcache_put (p, tc_idx);
	    return;
	  }
      }
  }
#endif
```

The chunk being freed is variable `e`. We can see here that before `tcache_put()` is called on it, there is a check being done:

```c
if (__glibc_unlikely (e->key == tcache))
```

The check determines whether the `key` field of the chunk `e` is set to the address of the `tcache_perthread_struct` already. Remember that **this happens when it is put into the tcache with `tcache_put()`**! If the pointer is already there, there is a **very** high chance that it's because the chunk has **already been freed**, in which case it's a double-free!

It's not a 100% guaranteed double-free though - as the comment above it says:

> This test succeeds on double free.  However, we don't 100% trust it (it also matches random payload data at a 1 in 2^\<size\_t> chance), so verify it's not an unlikely coincidence before aborting.

There is a `1/2^<size_t>` chance that the `key` being `tcache_perthread_struct` already is a coincidence. To verify, it simply iterates through the tcache bin and compares the chunks to the one being freed:

```c
tcache_entry *tmp;
LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
for (tmp = tcache->entries[tc_idx]; tmp; tmp = tmp->next)
    if (tmp == e)
        malloc_printerr ("free(): double free detected in tcache 2");
/* If we get here, it was a coincidence.  We've wasted a
   few cycles, but don't abort.  */
```

Iterates through each entry, calls it `tmp` and compares it to `e`. If equal, it detected a double-free.

{% hint style="danger" %}
You can think of the `key` as an effectively random value (due to ASLR) that gets checked against, and if it's the correct value then something is suspicious.
{% endhint %}

So, what can we do against this? Well, the `tcache_perthread_struct` is always the first chunk allocated on the heap, so it's always located at `heap + 0x10` (due to chunk metadata). A heap leak is therefore enough to bypass this protection!

Note that creating fake overlapping chunks to control `fd` is **not** affected by this as glibc only checks if the address is exactly identical.

***

In glibc 2.34, the `key` field was [updated from a `tcache_perthread_struct *` to a `uintptr_t`](https://elixir.bootlin.com/glibc/glibc-2.34/source/malloc/malloc.c#L3017). Instead of `tcache_put()` setting `key` to the location of the `tcache_perthread_struct`, it sets it to [a new variable called `tcache_key`](https://elixir.bootlin.com/glibc/glibc-2.34/source/malloc/malloc.c#L3068):

```c
static __always_inline void tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache_key;

  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

{% hint style="info" %}
Note the [Safe-Linking `PROTECT_PTR`](safe-linking.md) as well!
{% endhint %}

What is `tcache_key`? It's defined [here](https://elixir.bootlin.com/glibc/glibc-2.34/source/malloc/malloc.c#L3035) and set directly below, in the [`tcache_key_initialise()`](https://elixir.bootlin.com/glibc/glibc-2.34/source/malloc/malloc.c#L3047) function:

```c
static void tcache_key_initialize (void)
{
  if (__getrandom (&tcache_key, sizeof(tcache_key), GRND_NONBLOCK)
      != sizeof (tcache_key))
    {
      tcache_key = random_bits ();
#if __WORDSIZE == 64
      tcache_key = (tcache_key << 32) | random_bits ();
#endif
    }
}
```

It attempts to call `__getrandom()`, which is defined as a stub [here](https://elixir.bootlin.com/glibc/glibc-2.34/source/stdlib/getrandom.c#L25) and for Linux [here](https://elixir.bootlin.com/glibc/glibc-2.34/source/sysdeps/unix/sysv/linux/getrandom.c#L27); it just uses a syscall to read `n` random bytes. If that fails for some reason, it calls the [`random_bits()`](https://elixir.bootlin.com/glibc/glibc-2.34/source/include/random-bits.h#L31) function instead, which generates a pseudo-random number seeded by the time. Long story short: **`tcache_key` is random**. The [check in `_int_free()` still exists](https://elixir.bootlin.com/glibc/glibc-2.34/source/malloc/malloc.c#L4346), and the operation is the same, just it's completely random rather than based on ASLR. As the comment above it says

> The value of tcache\_key does not really have to be a cryptographically secure random number.  It only needs to be arbitrary enough so that it does not collide with values present in applications.  \[...]

This means that a heap leak is **no longer enough** to bypass the protection - we need to leak the random value itself if we intend to do a double-free. Creating fake overlapping chunks to control `fd` is still **not** affected.
