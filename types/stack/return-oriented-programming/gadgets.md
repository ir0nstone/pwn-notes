---
description: Controlling execution with snippets of code
---

# Gadgets

Gadgets are small snippets of code followed by a `ret` instruction, e.g. `pop rdi; ret`. We can manipulate the `ret` of these gadgets in such a way as to string together a large chain of them to do what we want.

### Example

Let's for a minute pretend the stack looks like this during the execution of a `pop rdi; ret` gadget.

![](../../../.gitbook/assets/image%20%2819%29.png)

What happens is fairly obvious - `0x10` gets popped into `rdi` as it is at the top of the stack during the `pop rdi`. Once the `pop` occurs, `rsp` moves:

![](../../../.gitbook/assets/image%20%2821%29.png)

And since `ret` is equivalent to `pop rip`, `0x5655576724` gets moved into `rip`. Note how the stack is laid out for this.

### Utilising Gadgets

When we overwrite the return pointer, we overwrite the value pointed at by `rsp`. Once that value is popped, it points at the next value at the stack - but wait. We can overwrite the next value in the stack.

Let's say that we want to exploit a binary to jump to a `pop rdi; ret` gadget, pop `0x100` into `rdi` then jump to `flag()`. Let's step-by-step the execution.

![](../../../.gitbook/assets/image%20%2822%29.png)

On the _original_ `ret`, which we overwrite the return pointer for, we pop the gadget address in. Now `rip` moves to point to the gadget, and `rsp` moves to the next memory address.

![](../../../.gitbook/assets/image%20%2824%29.png)

`rsp` moves to the `0x100`; `rip` to the `pop rdi`. Now when we pop, `0x100` gets moved into `rdi`.

![](../../../.gitbook/assets/image%20%2820%29.png)

RSP moves onto the next items on the stack, the address of `flag()`. The `ret` is executed and `flag()` is called.

### Summary

Essentially, if the gadget pops values from the stack, simply place those values afterwards \(including the `pop rip` in `ret`\). If we want to pop `0x10` into `rdi` and then jump to `0x16`, our payload would look like this:

![](../../../.gitbook/assets/image%20%2823%29.png)

Note if you have multiple `pop` instructions, you can just add more values.

![](../../../.gitbook/assets/image%20%2825%29.png)

{% hint style="info" %}
We use `rdi` as an example because, if you remember, that's the register for the first parameter in 64-bit. This means control of this register using this gadget is important.
{% endhint %}

### Finding Gadgets

We can use the tool [`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget) to find possible gadgets.

```text
$ ROPgadget --binary vuln-64

Gadgets information
============================================================
0x0000000000401069 : add ah, dh ; nop dword ptr [rax + rax] ; ret
0x000000000040109b : add bh, bh ; loopne 0x40110a ; nop ; ret
0x0000000000401037 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401024
[...]
```

Combine it with `grep` to look for specific registers.

```text
$ ROPgadget --binary vuln-64 | grep rdi

0x0000000000401096 : or dword ptr [rdi + 0x404030], edi ; jmp rax
0x00000000004011db : pop rdi ; ret
```

