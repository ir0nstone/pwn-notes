---
description: The Buffer Overflow defence
---

# Stack Canaries

Stack Canaries are very simple - at the beginning of the function, a random value is placed on the stack. Before the program executes `ret`, the current value of that variable is compared to the initial: if they are the same, no buffer overflow has occurred.

If they are not, the attacker attempted to overflow to control the return pointer and the program crashes, often with a `***stack smashing detected***` error message.

> Note: On Linux, stack canaries end in `00`. This is so that they null-terminate any strings in case you make a mistake when using print functions.

## Bypassing Canaries

There are two ways to bypass a canary.

### Leaking it

This is quite broad and will differ from binary to binary, but the main aim is to read the value. The simplest option is using **format string** if it is present - the canary, like other local variables, is on the stack, so if we can leak values off the stack it's easy.

