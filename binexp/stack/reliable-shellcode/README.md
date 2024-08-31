---
description: 'Shellcode, but without the guesswork'
---

# Reliable Shellcode

## Utilising ROP

The problem with shellcode exploits as they are is that the locations of it are questionable - wouldn't it be cool if we could control where we wrote it to?

Well, we can.

Instead of writing shellcode directly, we can instead use some ROP to take in input again - except this time, we specify the location as somewhere we control.

## Using ESP

If you think about it, once the return pointer is popped off the stack ESP will points at whatever is after it in memory - after all, that's the entire basis of ROP. But what if we put shellcode there?

It's a crazy idea. But remember, ESP will point there. So what if we overwrite the return pointer with a `jmp esp` gadget! Once it gets popped off, ESP will point at the shellcode and thanks to the `jmp esp` it will be executed!

## ret2reg

**ret2reg** extends the use of `jmp esp` to the use of _any_ register that happens to point somewhere you need it to.

