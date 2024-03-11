# An Interactive Char Driver

Creating an interactive char driver is surprisingly simple, but there are a few traps along the way.

## Exposing it to the File System

This is by far the hardest part to understand, but honestly a _full_ understanding isn't really necessary. The new `intro_init` function looks like this:

```c
#define DEVICE_NAME "intro"
#define CLASS_NAME "intro"

// setting up the device
int major;
static struct class*  my_class  = NULL;
static struct device* my_device = NULL;

static int __init intro_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);    // explained later

    if ( major < 0 )
        printk(KERN_ALERT "[Intro] Error assigning Major Number!");
    
    // Register device class
    my_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(my_class)) {
        unregister_chrdev(major, DEVICE_NAME);
        printk(KERN_ALERT "[Intro] Failed to register device class\n");
    }

    // Register the device driver
    my_device = device_create(my_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(my_device)) {
        class_destroy(my_class);
        unregister_chrdev(major, DEVICE_NAME);
        printk(KERN_ALERT "[Intro] Failed to create the device\n");
    }

    return 0;
}
```

A **major number** is essentially the unique identifier to the kernel module. You can specify it using the first parameter of `register_chrdev`, but if you pass `0` it is automatically assigned an unused major number.

We then have to register the **class** and the **device**. In complete honesty, I don't quite understand what they do, but this code exposes the module to `/dev/intro`.

Note that on an error it calls `class_destroy` and `unregister_chrdev`:

## Cleaning it Up

These additional classes and devices have to be cleaned up in the `intro_exit` function, and we mark the **major number** as available:

```c
static void __exit intro_exit(void) {
    device_destroy(my_class, MKDEV(major, 0));              // remove the device
    class_unregister(my_class);                             // unregister the device class
    class_destroy(my_class);                                // remove the device class
    unregister_chrdev(major, DEVICE_NAME);                  // unregister the major number
    printk(KERN_INFO "[Intro] Closing!\n");
}
```

## Controlling I/O

In `intro_init`, the first line may have been confusing:

```c
major = register_chrdev(0, DEVICE_NAME, &fops);
```

The third parameter `fops` is where all the magic happens, allowing us to create handlers for operations such as `read` and `write`. A really simple one would look something like:

```c
static ssize_t intro_read(struct file *filp, char __user *buffer, size_t len, loff_t *off) {
    printk(KERN_ALERT "reading...");

    copy_to_user(buffer, "QWERTY", 6);

    return 0;
}

static struct file_operations fops = {
    .read = intro_read
};
```

The parameters to `intro_read` may be a bit confusing, but the 2nd and 3rd ones line up to the 2nd and 3rd parameters for the `read()` function itself:

```c
ssize_t read(int fd, void *buf, size_t count);
```

We then use the function `copy_to_user` to write `QWERTY` to the buffer passed in as a parameter!

## Full Code

```c
#include <linux/init.h>
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "intro"
#define CLASS_NAME "intro"

MODULE_AUTHOR("ir0nstone");
MODULE_DESCRIPTION("Interactive Drivers");
MODULE_LICENSE("GPL");

// setting up the device
int major;
static struct class*  my_class  = NULL;
static struct device* my_device = NULL;

static ssize_t intro_read(struct file *filp, char __user *buffer, size_t len, loff_t *off) {
    printk(KERN_ALERT "reading...");

    copy_to_user(buffer, "QWERTY", 6);

    return 0;
}

static struct file_operations fops = {
    .read = intro_read
};

static int __init intro_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);

    if ( major < 0 )
        printk(KERN_ALERT "[Intro] Error assigning Major Number!");
    
    // Register device class
    my_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(my_class)) {
        unregister_chrdev(major, DEVICE_NAME);
        printk(KERN_ALERT "[Intro] Failed to register device class\n");
    }

    // Register the device driver
    my_device = device_create(my_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(my_device)) {
        class_destroy(my_class);
        unregister_chrdev(major, DEVICE_NAME);
        printk(KERN_ALERT "[Intro] Failed to create the device\n");
    }

    return 0;
}

static void __exit intro_exit(void) {
    device_destroy(my_class, MKDEV(major, 0));              // remove the device
    class_unregister(my_class);                             // unregister the device class
    class_destroy(my_class);                                // remove the device class
    unregister_chrdev(major, DEVICE_NAME);                  // unregister the major number
    printk(KERN_INFO "[Intro] Closing!\n");
}

module_init(intro_init);
module_exit(intro_exit);

```

Simply use `sudo insmod` to load it, [as we did before](./#using-the-kernel-module).

## Testing The Module

Create a really basic `exploit.c`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main() {
    int fd = open("/dev/intro", O_RDWR);    // Open the device with RW access
    printf("FD: %d\n", fd);                 // print the file descriptor

    char buffer[6];
    memset(&buffer, 'A', 6);                // fill with As
    printf("%s\n", buffer);                 // print
    read(fd, buffer, 6);                    // read from module
    printf("%s\n", buffer);                 // print again
}
```

If the module is successfully loaded, the `read()` call should read `QWERTY` into `buffer`:

```
$ ./exploit

FD: 3
AAAAAA
QWERTY
```

Success!
