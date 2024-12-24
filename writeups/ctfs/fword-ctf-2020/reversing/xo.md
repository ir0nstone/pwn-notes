---
description: Messing with the XOR
---

# XO

## Overview

Let's try running the file:

```text
$ ./task 
Error while opening the file. Contact an admin!
: No such file or directory
```

Perhaps it wants a flag.txt file? Let's create one with the words `FwordCTF{flag_flaggety_flag}`:

```text
$ ./task 

input : 
test
4
input : 
pao
2
```

This isn't _quite_ counting the number of letters we enter. Let's see if the disassembly can shed any light on it.

## Disassembly

First thing we notice is that _every_ `libc` function is built into the binary due to the stripped names. We can confirm this with `rabin2`:

```text
$ rabin2 -I task
[...]
static  true
[...]
```

### Cleaning Up

Many of the functions can be handled using the return address and the general context. Some of the decompilation - especially the references to strings - may not have loaded in yet; make sure GHidra finishes analysing. We don't even need the exact C names, as long as we get the general gist it's all fine.

```c
void main(void)
{
  int min_length;
  void *flag;
  void *input;
  long lVar1;
  long **xored;
  ulong flag_length;
  ulong input_length;
  long **in_RCX;
  long **extraout_RDX;
  long **output;
  ulong in_R8;
  long *in_R9;
  int i;
  
  FUN_00400b7d();
  
  flag = malloc(0x32);
  input = malloc(0x32);
  lVar1 = read("flag.txt",&DAT_004ac8e8);
  if (lVar1 == 0) {
    puts("Error while opening the file. Contact an admin!\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  output = (long **)&DAT_004ac929;
  FUN_0040fd20(lVar1,&DAT_004ac929,flag);
  do {
    xored = (long **)malloc(0x32);
    FUN_00410cf0("input : ",output);
    scanf("%s");
    flag_length = strlen(flag);
    input_length = strlen(input);
    if (input_length < flag_length) {
      min_length = strlen(input);
    }
    else {
      min_length = strlen(flag);
    }
    i = 0;
    while (i < min_length) {
      in_RCX = (long **)(ulong)*(byte *)((long)input + (long)i);
      *(byte *)((long)xored + (long)i) =
           *(byte *)((long)flag + (long)i) ^ *(byte *)((long)input + (long)i);
      i = i + 1;
    }
    output = (long **)strlen(xored);
    FUN_0040f840(&DAT_004ac935);
    FUN_00420ab0(xored,output,extraout_RDX,in_RCX,in_R8,in_R9);
  } while( true );
}
```

The python equivalent of this is roughly

```python
value = ''

for x, y in zip(flag, input):
  value += chr(ord(x) ^ ord(y))

print(len(garbage))
```

In short, it's an **XOR** function.

### Working out the Flaw

To calculate the length of the string it uses

```c
output = (long **)strlen(xored);
```

The key here is `strlen` stops at a **null byte**. If you input a character with the same value as the flag character in that position, it will XOR to become `\x00`.

### Using the Flaw

We can test every possible character. If the returned value is one less than the length of the string, the last character is correct as it XORed to create a null byte.

To test different offsets we can pad using a value definitely not in the flag, such as `#`.

## Exploit

### Local

```python
from pwn import *
from string import printable

p = process('./task')

known = ''

while True:
    for char in printable:
        p.recvline()
        p.sendline('#' * len(known) + char)     # '#' won't be in it, so any null byte is definitely the char we test

        resp = int(p.recvline().strip())

        if resp == len(known):                  # if it's the same length as the known, then the char we sent XORed to a null byte
            log.info(f'Character is {char}')
            known += char                       # append it to what we know

            if char == '}':                     # if '}', probably the end of the flag - print and exit
                log.success(f'Flag: {known}')
                exit(0)
            
            break                               # we know the char, we can exit the for loop and run it again with a different known length
```

Now we can just switch out the process type on the remote server.

### Remote

```python
from pwn import *
from string import printable

if args.REMOTE:
    p = remote('xo.fword.wtf', 5554)
else:
    p = process('./task')

known = ''

while True:
    for char in printable:
        p.recvline()
        p.sendline('#' * len(known) + char)     # '#' won't be in it, so any null byte are definitely the char we test

        resp = int(p.recvline().strip())

        if resp == len(known):                  # if it's the same length as the known, then the char we sent XORed to a null byte
            log.info(f'Character is {char}')
            known += char                       # append it to what we know

            if char == '}':                     # if '}', probably the end of the flag - print and exit
                log.success(f'Flag: {known}')
                exit(0)
            
            break                               # we know the char, we can exit the for loop and run it again with a different known length
```

Flag: `NuL1_Byt35?15_IT_the_END?Why_i_c4nT_h4ndl3_That!`

