---
description: A more useful way to interact with the driver
---

# Interactivity with IOCTL

Linux contains a syscall called `ioctl`, which is often used to communicate with a driver. `ioctl()` takes three parameters:

* File Descriptor `fd`
* an `unsigned int`
* an `unsigned long`

The driver can be adapted to make the latter two virtually anything - perhaps a pointer to a struct or a string. In the driver source, the code looks along the lines of:

```c
static ssize_t ioctl_handler(struct file *file, unsigned int cmd, unsigned long arg) {
    printk("Command: %d; Argument: %d", cmd, arg);

    return 0;
}
```

But if you want, you can interpret `cmd` and `arg` as pointers if that is how you wish your driver to work.

To communicate with the driver in this case, you would use the `ioctl()` function, which you can import in C:

```c
#include <sys/ioctl.h>

// [...]

ioctl(fd, 0x100, 0x12345678);    // data is a string
```

