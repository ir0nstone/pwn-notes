# A Basic Kernel Interaction Challenge

## The Module

We're going to create a really basic authentication module that allows you to read the flag if you input the correct password. Here is the relevant code:

```c
#define PASSWORD    "p4ssw0rd"
#define FLAG        "flag{YES!}"
#define FAIL        "FAIL: Not Authenticated!"

static int authenticated = 0;

static ssize_t auth_read(struct file *filp, char __user *buf, size_t len, loff_t *off) {
    printk(KERN_ALERT "[Auth] Attempting to read flag...");

    if (authenticated) {
        copy_to_user(buf, FLAG, sizeof(FLAG));      // ignoring `len` here
        return 1;
    }

    copy_to_user(buf, FAIL, sizeof(FAIL));
    return 0;
}

static ssize_t auth_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
    char password_attempt[20];

    printk(KERN_ALERT "[Auth] Reading password from user...");

    copy_from_user(password_attempt, buf, count);

    if (!strcmp(password_attempt, PASSWORD)) {
        printk(KERN_ALERT "[Auth] Password correct!");
        authenticated = 1;
        return 1;
    }

    printk(KERN_ALERT "[Auth] Password incorrect!");

    return 0;
}
```

If we attempt to `read()` from the device, it checks the `authenticated` flag to see if it can return us the flag. If not, it sends back `FAIL: Not Authenticated!`.

In order to update `authenticated`, we have to `write()` to the kernel module. What we attempt to write it compared to `p4ssw0rd`. If it's not equal, nothing happens. If it is, `authenticated` is updated and the next time we `read()` it'll return the flag!

### Interacting

Let's first try and interact with the kernel by reading from it.

{% hint style="info" %}
Make sure you `sudo chmod 666 /dev/authentication`!
{% endhint %}

We'll start by opening the device and reading from it.

```c
int fd = open("/dev/authentication", O_RDWR);

char buffer[20];
read(fd, buffer, 20);
printf("%s\n", buffer);
```

{% hint style="info" %}
Note that in the module source code, the length of `read()` is completely disregarded, so we could make it any number at all! Try switching it to `1` and you'll see.
{% endhint %}

After compiling, we get that we are not authenticated:

<pre class="language-bash"><code class="lang-bash"><strong>$ ./exploit 
</strong>FAIL: Not Authenticated!
</code></pre>

Epic! Let's write the correct password to the device then try again. It's really important to send the null byte here! That's because `copy_from_user()` does not automatically add it, so the `strcmp` will fail otherwise!

```c
write(fd, "p4ssw0rd\0", 9);

read(fd, buffer, 20);
printf("%s\n", buffer);
```

It works!

```bash
$ ./exploit
FAIL: Not Authenticated!
flag{YES!}
```

Amazing! Now for something really important:

```bash
$ ./exploit 
flag{YES!}
flag{YES!}
```

The **state is preserved between connections**! Because the kernel module remains on, you will be authenticated until the module is reloaded (either via `rmmod` then `insmod`, or a system restart).

### Final Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main() {
    int fd = open("/dev/authentication", O_RDWR);

    char buffer[20];
    read(fd, buffer, 1);
    printf("%s\n", buffer);

    write(fd, "p4ssw0rd", 8);

    read(fd, buffer, 20);
    printf("%s\n", buffer);
}
```

{% file src="../../.gitbook/assets/basic_interaction (1).zip" %}
The Source Code
{% endfile %}

## Challenge - IOCTL

So, here's your challenge! Write the **same** kernel module, but using `ioctl` instead. Then write a program to interact with it and perform the same operations. ZIP file including both below, but no cheating! This is really good practise.

{% file src="../../.gitbook/assets/basic_authentication_ioctl.zip" %}
Potential Solution
{% endfile %}
