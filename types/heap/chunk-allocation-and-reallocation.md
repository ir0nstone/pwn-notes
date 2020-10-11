# Chunk Allocation and Reallocation

The bins exist to reuse chunks. Here we'll look at how that's done.

## Fastbins

Fastbins are probably the easiest to explain as they are sorted by size.

As mentioned, the last chunk to be placed in the bin is the first chunk reallocated. We can see this behaviour in a simple C program.

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char *a = malloc(20);
    char *b = malloc(20);
    char *c = malloc(20);
    
    printf("a: %p\nb: %p\nc: %p\n", a, b, c);

    puts("Freeing...");

    free(a);
    free(b);
    free(c);

    puts("Allocating...");

    char *d = malloc(20);
    char *e = malloc(20);
    char *f = malloc(20);

    printf("d: %p\ne: %p\nf: %p\n", d, e, f);
}
```

And we get:

```text
a: 0x2292010
b: 0x2292030
c: 0x2292050
Freeing...
Allocating...
d: 0x2292050
e: 0x2292030
f: 0x2292010
```

You can see the behaviour here. This specific fastbin progresses as follows:

```text
### a/b/c allocated
HEAD -> TAIL
### a freed
HEAD -> a -> TAIL
### b freed
HEAD -> b -> a -> TAIL
### c freed
HEAD -> c -> b -> a -> TAIL
### d allocated
HEAD -> b -> a -> TAIL
### e allocated
HEAD -> a -> TAIL
### f allocated
```

As you can see, the chunk `a` gets reassigned to chunk `f`, `b` to `e` and `c` to `d`.

So, if we `free()` a chunk, there's a good chance our next `malloc()` - if it's of the same size - will use the same chunk.

