---
description: Reading memory off the stack
---

# Format String Bug

Format String is a dangerous bug that is easily exploitable. If manipulated correctly, you can leverage it to perform powerful actions such as reading from and writing to arbitrary memory locations.

### Why it exists

In C, certain functions can take "format specifier" within strings. Let's look at an example:

```c
int value = 1205;

printf("The value is %d as decimal, %f as float and 0x%x as hex", value, (double) value, value);
```



