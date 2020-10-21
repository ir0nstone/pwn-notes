# Double-Free Protections

It wouldn't be fun if there were no protections, right?

Using Xenial Xerus, try running:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    int *a = malloc(0x50);

    free(a);
    free(a);
    
    return 1;
}
```

Notice that it throws an error.

### Double Free or Corruption \(Fasttop\)

> Is the chunk at the top of the bin the same as the chunk being inserted

For example, the following code still works:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    int *a = malloc(0x50);
    int *b = malloc(0x50);

    free(a);
    free(b);
    free(a);
    
    return 1;
}
```

I did actually have a working binary to show how to exploit this, but sadly got tripped up by the next protection so it might be a while.

### malloc\(\): memory corruption \(fast\)

> When removing the chunk from a fastbin, make sure the size falls into the fastbin's range

The previous protection could be bypassed by freeing another chunk inbetween the double-free and just doing a bit more work that way, but then you fall into this trap.

Namely, if you overwrite `fd` with something like `0x08041234`, you have to make sure the metadata fits - i.e. the size ahead of the data is completely correct - and that makes it harder, because you can't just write into the GOT, unless you get lucky.

