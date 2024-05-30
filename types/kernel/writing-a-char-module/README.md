# Writing a Char Module

## The Code

Writing a Char Module is suprisingly simple. First, we specify what happens on `init` (loading of the module) and `exit` (unloading of the module). We need some special headers for this.

```c
#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("Mine!");

static int intro_init(void) {
    printk(KERN_ALERT "Custom Module Started!\n");
    return 0;
}

static void intro_exit(void) {
    printk(KERN_ALERT "Custom Module Stopped :(\n");
}

module_init(intro_init);
module_exit(intro_exit);

```

It looks simple, because it _is_ simple. For now, anyway.

First we set the license, because otherwise we get a warning, and I hate warnings. Next we tell the module what to do on load (`intro_init()`) and unload (`intro_exit()`). Note we put parameters as `void`, this is because kernel modules are very picky about [requiring parameters](https://stackoverflow.com/questions/40309582/kernel-module-compiler-error-function-declaration-isn-t-a-prototype-werror-st) (even if just void).

We then register the purposes of the functions using `module_init()` and `module_exit()`.

Note that we use `printk` rather than `printf`. GLIBC doesn't exist in kernel mode, and instead we use C's in-built kernel functionality. `KERN_ALERT` is specifies the type of message sent, and [there are many more types](https://www.kernel.org/doc/html/latest/core-api/printk-basics.html).

## Compiling

Compiling a Kernel Object can seem a little more complex as we use a [`Makefile`](https://opensource.com/article/18/8/what-how-makefile), but it's surprisingly simple:

```
obj-m += intro.o
 
all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
```

`$(MAKE)` is a special flag that effectively calls `make`, but it propagate all same flags that _our_ `Makefile` was called with. So, for example, if we call

```bash
$ make -j 8
```

Then `$(MAKE)` will become `make -j 8`. Essentially, `$(MAKE)` is `make`, which compiles the module. The files produced are defined at the top as `obj-m`. Note that compilation is **unique per kernel**, which is why the compiling process uses your unique kernel build section.

## Using the Kernel Module

Now we've got a `ko` file compiled, we can add it to the list of active modules:

```
$ sudo insmod test.ko
```

If it's successful, there will be no response. But where did it print to?

Remember, the kernel program has no concept of userspace; it does not know you ran it, nor does it bother communicating with userspace. Instead, this code runs in the kernel, and we can check the output using `sudo dmesg`.

```
$ sudo dmesg | tail -n 1
[ 3645.657331] Custom Module Started!
```

Here we grab the last line using `tail` - as you can see, our `printk` is called!

Now let's unload the module:

```
$ sudo rmmod test
$ sudo dmesg | tail -n 1
[ 4046.904898] Custom Module Stopped :(
```

And there our `intro_exit` is called.

{% hint style="info" %}
You can view currently loaded modules using the `lsmod` command
{% endhint %}
