---
description: A practical example
---

# Debugging a Kernel Module

## Trying on the Latest Kernel

Let's try and run our previous code, but with the latest kernel version (as of writing, `6.10-rc5`). The offsets of `commit_creds` and `prepare_kernel_cred()` are as follows, and we'll update `exploit.c` with the new values:

```c
commit_creds           0xffffffff81077390
prepare_kernel_cred    0xffffffff81077510
```

{% hint style="info" %}
The major number needs to be updated to `253` in `init` for this version! I've done it automatically, but it bears remembering if you ever try to create your own module.
{% endhint %}

{% file src="../../.gitbook/assets/rop_ret2usr_6.10.zip" %}

Instead of an elevated shell, we get a kernel panic, with the following data dump:

```
[    1.472064] BUG: kernel NULL pointer dereference, address: 0000000000000000
[    1.472064] #PF: supervisor read access in kernel mode
[    1.472064] #PF: error_code(0x0000) - not-present page
[    1.472064] PGD 22d9067 P4D 22d9067 PUD 22da067 PMD 0 
[    1.472064] Oops: Oops: 0000 [#1] SMP
[    1.472064] CPU: 0 PID: 32 Comm: exploit Tainted: G        W  O       6.10.0-rc5 #7
[    1.472064] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
[    1.472064] RIP: 0010:commit_creds+0x29/0x180
[    1.472064] Code: 00 f3 0f 1e fa 55 48 89 e5 41 55 65 4c 8b 2d 9e 80 fa 7e 41 54 53 4d 8b a5 98 05 00 00 4d 39 a5 a0 05 00 00 0f 85 3b 01 00 00 <48> 8b 07 48 89 fb 48 85 c0 0f 8e 2e 01 07
[    1.472064] RSP: 0018:ffffc900000d7e30 EFLAGS: 00000246
[    1.472064] RAX: 0000000000000000 RBX: 00000000004a8220 RCX: ffffffff81077390
[    1.472064] RDX: 0000000000000000 RSI: 00000000ffffffea RDI: 0000000000000000
[    1.472064] RBP: ffffc900000d7e48 R08: ffffffff818a7a28 R09: 0000000000004ffb
[    1.472064] R10: 00000000000000a5 R11: ffffffff818909b8 R12: ffff88800219b480
[    1.472064] R13: ffff888002202e00 R14: 0000000000000000 R15: 0000000000000000
[    1.472064] FS:  000000001b323380(0000) GS:ffff888007800000(0000) knlGS:0000000000000000
[    1.472064] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    1.472064] CR2: 0000000000000000 CR3: 00000000022d7000 CR4: 00000000000006b0
[    1.472064] Call Trace:
[    1.472064]  <TASK>
[    1.472064]  ? show_regs+0x64/0x70
[    1.472064]  ? __die+0x24/0x70
[    1.472064]  ? page_fault_oops+0x14b/0x420
[    1.472064]  ? search_extable+0x2b/0x30
[    1.472064]  ? commit_creds+0x29/0x180
[    1.472064]  ? search_exception_tables+0x4f/0x60
[    1.472064]  ? fixup_exception+0x26/0x2d0
[    1.472064]  ? kernelmode_fixup_or_oops.constprop.0+0x58/0x70
[    1.472064]  ? __bad_area_nosemaphore+0x15d/0x220
[    1.472064]  ? find_vma+0x30/0x40
[    1.472064]  ? bad_area_nosemaphore+0x11/0x20
[    1.472064]  ? exc_page_fault+0x284/0x5c0
[    1.472064]  ? asm_exc_page_fault+0x2b/0x30
[    1.472064]  ? abort_creds+0x30/0x30
[    1.472064]  ? commit_creds+0x29/0x180
[    1.472064]  ? x64_sys_call+0x146c/0x1b10
[    1.472064]  ? do_syscall_64+0x50/0x110
[    1.472064]  ? entry_SYSCALL_64_after_hwframe+0x4b/0x53
[    1.472064]  </TASK>
[    1.472064] Modules linked in: kernel_rop(O)
[    1.472064] CR2: 0000000000000000
[    1.480065] ---[ end trace 0000000000000000 ]---
[    1.480065] RIP: 0010:commit_creds+0x29/0x180
[    1.480065] Code: 00 f3 0f 1e fa 55 48 89 e5 41 55 65 4c 8b 2d 9e 80 fa 7e 41 54 53 4d 8b a5 98 05 00 00 4d 39 a5 a0 05 00 00 0f 85 3b 01 00 00 <48> 8b 07 48 89 fb 48 85 c0 0f 8e 2e 01 07
[    1.484065] RSP: 0018:ffffc900000d7e30 EFLAGS: 00000246
[    1.484065] RAX: 0000000000000000 RBX: 00000000004a8220 RCX: ffffffff81077390
[    1.484065] RDX: 0000000000000000 RSI: 00000000ffffffea RDI: 0000000000000000
[    1.484065] RBP: ffffc900000d7e48 R08: ffffffff818a7a28 R09: 0000000000004ffb
[    1.484065] R10: 00000000000000a5 R11: ffffffff818909b8 R12: ffff88800219b480
[    1.484065] R13: ffff888002202e00 R14: 0000000000000000 R15: 0000000000000000
[    1.484065] FS:  000000001b323380(0000) GS:ffff888007800000(0000) knlGS:0000000000000000
[    1.484065] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    1.484065] CR2: 0000000000000000 CR3: 00000000022d7000 CR4: 00000000000006b0
[    1.488065] Kernel panic - not syncing: Fatal exception
[    1.488065] Kernel Offset: disabled
[    1.488065] ---[ end Kernel panic - not syncing: Fatal exception ]---
```

I could have left this part out of my blog, but it's valuable to know a bit more about debugging the kernel and reading error messages. I actually came across this issue while [trying to get the previous section working](kernel-rop-ret2usr.md), so it happens to all of us!

One thing that we can notice is that, the error here is listed as a **NULL pointer dereference** error. We can see that the error is thrown in `commit_creds()`:

```
[    1.480065] RIP: 0010:commit_creds+0x29/0x180
```

We can [check the source here](https://elixir.bootlin.com/linux/v6.10-rc5/source/kernel/cred.c#L392), but chances are that the parameter passed to `commit_creds()` is NULL - this appears to be the case, since RDI is shown to be `0` above!

### Opening a GDBserver

In our `run.sh` script, we now include the `-s` flag. This flag opens up a GDB server on port `1234`, so we can connect to it and debug the kernel. Another useful flag is `-S`, which will automatically pause the kernel on load to allow us to debug, but that's not necessary here.

What we'll do is pause our `exploit` binary just before the `write()` call by using `getchar()`, which will hang until we hit `Enter` or something similar. Once it pauses, we'll hook on with GDB. Knowing the address of `commit_creds()` is `0xffffffff81077390`, we can set a breakpoint there.

```
$ gdb kernel_rop.ko
pwndbg> target remote :1234
pwndbg> b *0xffffffff81077390
```

We then continue with `c` and go back to the VM terminal, where we hit `Enter` to continue the exploit. Coming back to GDB, it has hit the breakpoint, and we can see that RDI is indeed `0`:

```
pwndbg> info reg rdi
rdi            0x0                 0
```

This explains the NULL dereference. RAX is also `0`, in fact, so it's not a problem with the `mov`:

```
pwndbg> info reg rax
rax            0x0                 0
```

This means that `prepare_kernel_cred()` is returning `NULL`. Why is that? It didn't do that before!

Let's compare the differences in `prepare_kernel_cred()` code between kernel [version 6.1](https://elixir.bootlin.com/linux/v6.1.96/source/kernel/cred.c#L712) and [version 6.10](https://elixir.bootlin.com/linux/v6.10-rc5/source/kernel/cred.c#L629):

{% tabs %}
{% tab title="6.1" %}
```c
struct cred *prepare_kernel_cred(struct task_struct *daemon)
{
	const struct cred *old;
	struct cred *new;

	new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
	if (!new)
		return NULL;

	kdebug("prepare_kernel_cred() alloc %p", new);

	if (daemon)
		old = get_task_cred(daemon);
	else
		old = get_cred(&init_cred);

	validate_creds(old);

	*new = *old;
	new->non_rcu = 0;
	atomic_long_set(&new->usage, 1);
	set_cred_subscribers(new, 0);
	get_uid(new->user);
	get_user_ns(new->user_ns);
	get_group_info(new->group_info);

	// [...]
	
	if (security_prepare_creds(new, old, GFP_KERNEL_ACCOUNT) < 0)
		goto error;

	put_cred(old);
	validate_creds(new);
	return new;

error:
	put_cred(new);
	put_cred(old);
	return NULL;
}
```


{% endtab %}

{% tab title="6.10" %}
```c
struct cred *prepare_kernel_cred(struct task_struct *daemon)
{
	const struct cred *old;
	struct cred *new;

	if (WARN_ON_ONCE(!daemon))
		return NULL;

	new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
	if (!new)
		return NULL;

	kdebug("prepare_kernel_cred() alloc %p", new);

	old = get_task_cred(daemon);

	*new = *old;
	new->non_rcu = 0;
	atomic_long_set(&new->usage, 1);
	get_uid(new->user);
	get_user_ns(new->user_ns);
	get_group_info(new->group_info);

	// [...]

	new->ucounts = get_ucounts(new->ucounts);
	if (!new->ucounts)
		goto error;

	if (security_prepare_creds(new, old, GFP_KERNEL_ACCOUNT) < 0)
		goto error;

	put_cred(old);
	return new;

error:
	put_cred(new);
	put_cred(old);
	return NULL;
}
```


{% endtab %}
{% endtabs %}

The last and first parts are effectively identical, so there's no issue there. The issue arises in the way it handles a NULL argument. On 5.10, it treats it as using `init_task`:

```c
if (daemon)
    old = get_task_cred(daemon);
else
    old = get_cred(&init_cred);
```

i.e. if `daemon` is NULL, use `init_task`. On 6.10, the behaviour is altogether different:

```c
if (WARN_ON_ONCE(!daemon))
    return NULL;
```

If `daemon` is NULL, return NULL - hence our issue!

Unfortunately, there's no way to bypass this easily! We can fake `cred` structs, and if we can leak `init_task` we can use that memory address as well, but it's no longer as simple as calling `prepare_kernel_cred(0)`!
