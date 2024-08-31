---
description: Lack of space for ROP
---

# Stack Pivoting

## Overview

**Stack Pivoting** is a technique we use when we lack space on the stack - for example, we have 16 bytes past RIP. In this scenario, we're not able to complete a full ROP chain.

During Stack Pivoting, we take control of the **RSP** register and "fake" the location of the stack. There are a few ways to do this.

### pop rsp gadget

Possibly the simplest, but also the least likely to exist. If there is one of these, you're quite lucky.

### xchg &lt;reg&gt;, rsp

If you can find a `pop <reg>` gadget, you can then use this `xchg` gadget to swap the values with the ones in RSP. Requires about 16 bytes of stack space after the saved return pointer:

```text
pop <reg>                <=== return pointer
<reg value>
xchg <rag>, rsp
```

### leave; ret

This is a _very_ interesting way of stack pivoting, and it only requires 8 bytes.

Every function \(except `main`\) is ended with a `leave; ret` gadget. `leave` is equivalent to

```text
mov rsp, rbp
pop rbp
```

Note that the function ending therefore looks like

```text
mov rsp, rbp
pop rbp
pop rip
```

That means that when we overwrite RIP the 8 bytes before that overwrite RBP \(you may have noticed this before\). So, cool - we can overwrite `rbp` using `leave`. How does that help us?

Well if we look at `leave` again, we noticed the value in RBP gets moved to RSP! So if we call overwrite RBP then overwrite RIP with the address of `leave; ret` again, the value in RBP gets moved to RSP. And, even better, we don't need any more stack space than just overwriting RIP, making it _very_ compressed.

