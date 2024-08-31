---
description: A more in-depth look into parameters for 32-bit and 64-bit programs
---

# Calling Conventions

## One Parameter

{% file src="../../../.gitbook/assets/calling-conventions-one-param.zip" caption="Calling Conventions - One Parameter" %}

## Source

Let's have a quick look at the source:

```c
#include <stdio.h>

void vuln(int check) {
    if(check == 0xdeadbeef) {
        puts("Nice!");
    } else {
        puts("Not nice!");
    }
}

int main() {
    vuln(0xdeadbeef);
    vuln(0xdeadc0de);
}
```

Pretty simple.

If we run the 32-bit and 64-bit versions, we get the same output:

```text
Nice!
Not nice!
```

Just what we expected.

### Analysing 32-bit

Let's open the binary up in radare2 and disassemble it.

```text
$ r2 -d -A vuln-32
$ s main; pdf

0x080491ac      8d4c2404       lea ecx, [argv]
0x080491b0      83e4f0         and esp, 0xfffffff0
0x080491b3      ff71fc         push dword [ecx - 4]
0x080491b6      55             push ebp
0x080491b7      89e5           mov ebp, esp
0x080491b9      51             push ecx
0x080491ba      83ec04         sub esp, 4
0x080491bd      e832000000     call sym.__x86.get_pc_thunk.ax
0x080491c2      053e2e0000     add eax, 0x2e3e
0x080491c7      83ec0c         sub esp, 0xc
0x080491ca      68efbeadde     push 0xdeadbeef
0x080491cf      e88effffff     call sym.vuln
0x080491d4      83c410         add esp, 0x10
0x080491d7      83ec0c         sub esp, 0xc
0x080491da      68dec0adde     push 0xdeadc0de
0x080491df      e87effffff     call sym.vuln
0x080491e4      83c410         add esp, 0x10
0x080491e7      b800000000     mov eax, 0
0x080491ec      8b4dfc         mov ecx, dword [var_4h]
0x080491ef      c9             leave
0x080491f0      8d61fc         lea esp, [ecx - 4]
0x080491f3      c3             ret
```

If we look closely at the calls to `sym.vuln`, we see a pattern:

```text
push 0xdeadbeef
call sym.vuln
[...]
push 0xdeadc0de
call sym.vuln
```

We literally `push` the parameter to the stack before calling the function. Let's break on `sym.vuln`.

```text
[0x080491ac]> db sym.vuln
[0x080491ac]> dc
hit breakpoint at: 8049162
[0x08049162]> pxw @ esp
0xffdeb54c      0x080491d4 0xdeadbeef 0xffdeb624 0xffdeb62c
```

The first value there is the **return pointer** that we talked about before - the second, however, is the parameter. This makes sense because the return pointer gets pushed during the `call`, so it should be at the top of the stack. Now let's disassemble `sym.vuln`.

```text
┌ 74: sym.vuln (int32_t arg_8h);
│           ; var int32_t var_4h @ ebp-0x4
│           ; arg int32_t arg_8h @ ebp+0x8
│           0x08049162 b    55             push ebp
│           0x08049163      89e5           mov ebp, esp
│           0x08049165      53             push ebx
│           0x08049166      83ec04         sub esp, 4
│           0x08049169      e886000000     call sym.__x86.get_pc_thunk.ax
│           0x0804916e      05922e0000     add eax, 0x2e92
│           0x08049173      817d08efbead.  cmp dword [arg_8h], 0xdeadbeef
│       ┌─< 0x0804917a      7516           jne 0x8049192
│       │   0x0804917c      83ec0c         sub esp, 0xc
│       │   0x0804917f      8d9008e0ffff   lea edx, [eax - 0x1ff8]
│       │   0x08049185      52             push edx
│       │   0x08049186      89c3           mov ebx, eax
│       │   0x08049188      e8a3feffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x0804918d      83c410         add esp, 0x10
│      ┌──< 0x08049190      eb14           jmp 0x80491a6
│      │└─> 0x08049192      83ec0c         sub esp, 0xc
│      │    0x08049195      8d900ee0ffff   lea edx, [eax - 0x1ff2]
│      │    0x0804919b      52             push edx
│      │    0x0804919c      89c3           mov ebx, eax
│      │    0x0804919e      e88dfeffff     call sym.imp.puts           ; int puts(const char *s)
│      │    0x080491a3      83c410         add esp, 0x10
│      │    ; CODE XREF from sym.vuln @ 0x8049190
│      └──> 0x080491a6      90             nop
│           0x080491a7      8b5dfc         mov ebx, dword [var_4h]
│           0x080491aa      c9             leave
└           0x080491ab      c3             ret
```

Here I'm showing the **full** output of the command because a lot of it is relevant. `radare2` does a great job of detecting local variables - as you can see at the top, there is one called `arg_8h`. Later this same one is compared to `0xdeadbeef`:

```text
cmp dword [arg_8h], 0xdeadbeef
```

Clearly that's our parameter.

So now we know, when there's one parameter, it gets pushed to the stack so that the stack looks like:

```text
return address        param_1
```

### Analysing 64-bit

Let's disassemble `main` again here.

```text
0x00401153      55             push rbp
0x00401154      4889e5         mov rbp, rsp
0x00401157      bfefbeadde     mov edi, 0xdeadbeef
0x0040115c      e8c1ffffff     call sym.vuln
0x00401161      bfdec0adde     mov edi, 0xdeadc0de
0x00401166      e8b7ffffff     call sym.vuln
0x0040116b      b800000000     mov eax, 0
0x00401170      5d             pop rbp
0x00401171      c3             ret
```

Hohoho, it's different. As we mentioned before, the parameter gets moved to `rdi` \(in the disassembly here it's `edi`, but `edi` is just the lower 32 bits of `rdi`, and the parameter is only 32 bits long, so it says `EDI` instead\). If we break on `sym.vuln` again we can check `rdi` with the command

```text
dr rdi
```

{% hint style="info" %}
Just `dr` will display all registers
{% endhint %}

```text
[0x00401153]> db sym.vuln 
[0x00401153]> dc
hit breakpoint at: 401122
[0x00401122]> dr rdi
0xdeadbeef
```

Awesome.

{% hint style="info" %}
Registers are used for parameters, but the return address is still pushed onto the stack and in ROP is placed right after the function address
{% endhint %}

## Multiple Parameters

{% file src="../../../.gitbook/assets/calling-convention-multi-param.zip" caption="Calling Conventions - Multiple Parameters" %}

### Source

```c
#include <stdio.h>

void vuln(int check, int check2, int check3) {
    if(check == 0xdeadbeef && check2 == 0xdeadc0de && check3 == 0xc0ded00d) {
        puts("Nice!");
    } else {
        puts("Not nice!");
    }
}

int main() {
    vuln(0xdeadbeef, 0xdeadc0de, 0xc0ded00d);
    vuln(0xdeadc0de, 0x12345678, 0xabcdef10);
}
```

### 32-bit

We've seen the _full_ disassembly of an almost identical binary, so I'll only isolate the important parts.

```text
0x080491dd      680dd0dec0     push 0xc0ded00d
0x080491e2      68dec0adde     push 0xdeadc0de
0x080491e7      68efbeadde     push 0xdeadbeef
0x080491ec      e871ffffff     call sym.vuln
[...]
0x080491f7      6810efcdab     push 0xabcdef10
0x080491fc      6878563412     push 0x12345678
0x08049201      68dec0adde     push 0xdeadc0de
0x08049206      e857ffffff     call sym.vuln
```

It's just as simple - `push` them in reverse order of how they're passed in. The reverse order becomes helpful when you `db sym.vuln` and print out the stack.

```text
[0x080491bf]> db sym.vuln
[0x080491bf]> dc
hit breakpoint at: 8049162
[0x08049162]> pxw @ esp
0xffb45efc      0x080491f1 0xdeadbeef 0xdeadc0de 0xc0ded00d
```

So it becomes quite clear how more parameters are placed on the stack:

```text
return pointer        param1        param2        param3        [...]        paramN
```

### 64-bit

```text
0x00401170      ba0dd0dec0     mov edx, 0xc0ded00d
0x00401175      bedec0adde     mov esi, 0xdeadc0de
0x0040117a      bfefbeadde     mov edi, 0xdeadbeef
0x0040117f      e89effffff     call sym.vuln
0x00401184      ba10efcdab     mov edx, 0xabcdef10
0x00401189      be78563412     mov esi, 0x12345678
0x0040118e      bfdec0adde     mov edi, 0xdeadc0de
0x00401193      e88affffff     call sym.vuln
```

So as well as `rdi`, we also push to `rdx` and `rsi` \(or, in this case, their lower 32 bits\).

## Bigger 64-bit values

Just to show that it is in fact ultimately `rdi` and not `edi` that is used, I will alter the original one-parameter code to utilise a bigger number:

```c
#include <stdio.h>

void vuln(long check) {
    if(check == 0xdeadbeefc0dedd00d) {
        puts("Nice!");
    }
}

int main() {
    vuln(0xdeadbeefc0dedd00d);
}
```

If you disassemble `main`, you can see it disassembles to

```text
movabs rdi, 0xdeadbeefc0ded00d
call sym.vuln
```

{% hint style="info" %}
`movabs` can be used to encode the `mov` instruction for 64-bit instructions - treat it as if it's a `mov`.
{% endhint %}



