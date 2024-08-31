---
description: Quick shells and pointers
---

# One Gadgets and Malloc Hook

A `one_gadget` is simply an `execve("/bin/sh")` command that is present in gLIBC, and this can be a quick win with GOT overwrites - next time the function is called, the `one_gadget` is executed and the shell is popped.

`__malloc_hook` is a feature in C. The [Official GNU site](https://www.gnu.org/software/libc/manual/html_node/Hooks-for-Malloc.html) defines `__malloc_hook`  as:

> The value of this variable is a pointer to the function that `malloc` uses whenever it is called.

To summarise, when you call `malloc()` the function `__malloc_hook` points to also gets called - so if we can overwrite this with, say, a `one_gadget`, and somehow trigger a call to `malloc()`, we can get an easy shell.

#### Finding One\_Gadgets

Luckily there is a tool written in **Ruby** called `one_gadget`. To install it, run:

```text
gem install one_gadget
```

And then you can simply run

```text
one_gadget libc
```

{% hint style="info" %}
For most one\_gadgets, certain criteria have to be met. This means they won't all work - in fact, **none** of them may work.
{% endhint %}

#### Triggering malloc\(\)

Wait a sec - isn't `malloc()` a _heap_ function? How will we use it on the stack? Well, you can actually trigger `malloc` by calling `printf("%10000$c")` \(this allocates too many bytes for the stack, forcing libc to allocate the space on the heap instead\). So, if you have a format string vulnerability, calling malloc is trivial.

#### Practise

This is a hard technique to give you practise on, due to the fact that your `libc` version may not even have working `one_gadgets`. As such, feel free to play around with the GOT overwrite binary and see if you can get a `one_gadget` working.

Remember, the value given by the `one_gadget` tool needs to be added to libc base as it's just an offset.

