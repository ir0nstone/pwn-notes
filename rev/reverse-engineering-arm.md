---
description: >-
  Just a ragged collection of notes before I do anything proper - do not take
  this as gospel! I am doing ARM reversing on my M1 MacBook for fun...
---

# Reverse Engineering ARM

ARM works a bit differently to intel x86 architecture in the way it uses registers and how instructions are formed.

## Registers

* `SP` - Stack Pointer (same as ESP - points to top of the stack)
* `x29` - the Frame Pointer, `FP`, points to the base of the current functions stack frame (similar to EBP)
* `x30` - the Link Register, `LR`, which stores the return address of a function (the return pointer)
* `PC` - the Program Counter (aka Instruction Pointer) pointing to the next&#x20;

The calling convention in ARM works similarly to x86:

```
// drop down SP
sub sp, sp, 0x20

// Save FP and LR to the stack
stp x29, x30, [var_10h]

// Set up a new stack frame by updating x29 to SP+0x10
add x29, sp, 0x10

// ... function execution ...

// Restore FP and LR
ldp X29, X30, [SP], [var_10h]

// Return
ret
```

Even though it does roughly the same stuff, there are a few differences between x86 and ARM64.

Firstly, a lot of instructions take 3 parameters now:

```
sub sp, sp, 0x20
```

The first parameter here (as well as for other functions such as `add`) is the register to store the result in. In x86, we assume that the first register that we are adding also stores the result, but ARM makes it explicit.

The `stp` instruction has no direct x86 equivalent (as far as I am aware!). Essentially, the first two parameters provide registers and the third parameter tells it where in. memory to save the values. For example, the following instruction stores `x29` and `x30` to memory location `var_10h`:

```
stp x29, x30, [var_10h]
```

{% hint style="warning" %}
I'm not really sure what `var_10h` refers to - Cutter says\
`var_10h @ stack - 0x10`\
but I don't know exactly what it uses as a reference point - todo moment...
{% endhint %}

Finally, the `ret` instruction is executed. `ret` transfers the value in `x30` (`LR`) to `PC` to return execution to the next instruction after the call to the function.
