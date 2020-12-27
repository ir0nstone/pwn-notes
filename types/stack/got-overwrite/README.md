---
description: Hijacking functions
---

# GOT Overwrite

You may remember that the GOT stores the actual locations in `libc` of functions. Well, if we could overwrite an entry, we could gain code execution that way. Imagine the following code:

```c
char buffer[20];
gets(buffer);
printf(buffer);
```

Not only is there a buffer overflow and format string vulnerability here, but say we used that format string to overwrite the GOT entry of `printf` with the location of `system`. The code would essentially look like the following:

```c
char buffer[20];
gets(buffer);
system(buffer);
```

Bit of an issue? Yes. Our input is being passed directly to `system`.

