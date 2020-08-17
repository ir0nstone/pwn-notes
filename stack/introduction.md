---
description: An introduction to binary exploitation
---

# Introduction

**Binary Exploitation** is about finding vulnerabilities in programs and utilising them to do what you wish. Sometimes this can result in an authentication bypass or the leaking of classified information, but occasionally \(if you're lucky\) it can also result in Remote Code Execution \(RCE\). The most basic forms of binary exploitation occur on the **stack**, a region of memory that stores temporary variables created by functions in code.

When a new function is called, a memory address in the **calling** function is pushed to the stack - this way, the program knows where to return to once the called function finishes execution. Let's look at a basic binary to show this.

{% file src="../.gitbook/assets/introduction.zip" caption="Introduction" %}

## Analysis

The binary has two files - `source.c` and `vuln`; the latter is an `ELF` file, which is the executable format for Linux \(it is recommended to follow along with this with a Virtual Machine of your own, preferably Linux\).

We're gonna use a tool called `radare2` to analyse the behaviour of the binary when functions are called.

```text
$ r2 -d -A vuln
```

The `-d` runs it while the `-A` performs analysis. We can disassemble `main` with

```text
s main; pdf
```

`s main` seeks \(moves \)to main, while `pdf` stands for **P**rint **D**isassembly **F**unction \(literally just disassembles it\).

```text
0x080491ab      55             push ebp
0x080491ac      89e5           mov ebp, esp
0x080491ae      83e4f0         and esp, 0xfffffff0
0x080491b1      e80d000000     call sym.__x86.get_pc_thunk.ax
0x080491b6      054a2e0000     add eax, 0x2e4a
0x080491bb      e8b2ffffff     call sym.unsafe
0x080491c0      90             nop
0x080491c1      c9             leave
0x080491c2      c3             ret
```

The call to `unsafe` is at `0x080491bb`, so let's break there.

```text
db 0x080491bb
```

`db` stands for **d**ebug **b**reakpoint, and just sets a breakpoint. A breakpoint is simply somewhere which, when reached, pauses the program for you to run other commands. Now we run `dc` for **d**ebug **c**ontinue; this basically just carries on running the file.

It should break before `unsafe` is called; let's analyse the top of the stack now:

```text
[0x08049172]> pxw @ esp
0xff984af0 0xf7efe000 [...]
[...]
```

The first address, `0xff984aec`, is the position; the `0xf7efe000` is the value. Let's move one more instruction with `ds`, **d**ebug **s**tep, and check the stack again.

```text
[0x08049172]> pxw @ esp
0xff984aec  0x080491c0 0xf7efe000
```

Huh, something's been pushed onto the stack - the value `0x080491c0`. This looks like it's in the binary - but where?

```text
[...]
0x080491b6      054a2e0000     add eax, 0x2e4a
0x080491bb      e8b2ffffff     call sym.unsafe
0x080491c0      90             nop
[...]
```

Look at that - it's the instruction _after_ the call to `unsafe`. Why? This is how the program knows _where to return to after unsafe has finished_. Awesome.

## Weaknesses

But as we're interested in binary exploitation, let's see how we can possibly break this. First, let's disassemble unsafe and break on the `ret` instruction; `ret` is the equivalent of `pop eip`, which will get the saved return pointer we just analysed on the stack into the `eip` register. Then let's continue and spam a bunch of characters into the input and see how that could affect it.

```text
[0x08049172]> db 0x080491aa
[0x08049172]> dc
Overflow me
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Now let's read the value at the location the return pointer was at previously, which as we saw was `0xff984aec`.

```text
[0x080491aa]> pxw @ 0xff984aec
0xff984aec  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
```

Huh?

It's quite simple - we inputted _more data than the program expected_, which resulted in us overwriting more of the stack than the developer expected. The saved return pointer is _also_ on the stack, meaning we managed to overwrite it. As a result, on the `ret`, the value popped into `eip` won't be in the previous function but rather `0x41414141`. Let's check with `ds`.

```text
[0x080491aa]> ds
[0x41414141]>
```

And look at the new prompt - `0x41414141`. Let's run `dr eip` to make sure that's the value in `eip`:

```text
[0x41414141]> dr eip
0x41414141
```

Yup, it is! We've successfully hijacked the program execution! Let's see if it crashes when we let it run with `dc`.

```text
[0x41414141]> dc
child stopped with signal 11
[+] SIGNAL 11 errno=0 addr=0x41414141 code=1 ret=0
```

`radare2` is very useful and prints out the address that causes it to crash. If you cause the program to crash outside of a debugger, it will usually say `Segmentation Fault`, which _could_ mean a variety of things, but usually that you have overwritten EIP.

Of course, it is perfectly possible to prevent people from writing more characters than expected when making your program, usually using _other_ C functions such as `fgets()`; `gets()` is intrinsically unsafe because it _doesn't check the length of the input with where it is writing it_, meaning that the presence of `gets()` is **always** something you should check out in a program. Additionally, however, it is perfectly possible to give `fgets()` the wrong parameters, meaning it _still_ takes in too many characters.

## Summary

When a function calls another function, it

* pushes a return pointer to the stack so the called function knows where to return
* when the called function finishes execution, it pops it off the stack again

Because this value is saved on the stack, just like our local variables, if we write _more_ characters than the program expects, we can overwrite the value and redirect code execution to wherever we wish. Functions such as `fgets()` can prevent such easy overflow, but you should check how much is actually being read.

