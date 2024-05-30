---
description: >-
  Instructions for compiling the kernel with your own settings, as well as
  compiling kernel modules for a specific kernel version.
---

# Compiling, Customising and booting the Kernel

{% hint style="info" %}
This isn't necessary for learning how to write kernel exploits - all the important parts will be provided! This is just to help those hoping to write challenges of their own, or perhaps set up their own VMs for learning purposes.
{% endhint %}

## Prerequisites

```bash
$ apt-get install flex bison libelf-dev
```

{% hint style="info" %}
There may be other requirements, I just already had them. Check [here](https://github.com/torvalds/linux/blob/master/Documentation/process/changes.rst) for the full list.
{% endhint %}

## The Kernel

### Cloning

```bash
git clone https://github.com/torvalds/linux --depth=1
```

Use `--depth 1` to only get the last commit.

### Customise

Remove the current compilation configurations, as they are quite complex for our needs

```bash
$ cd linux
$ rm -f .config
```

Now we can create a **minimal configuration**, with almost all options disabled. A `.config` file is generated with the least features and drivers possible.

```bash
$ make allnoconfig
  YACC    scripts/kconfig/parser.tab.[ch]
  HOSTCC  scripts/kconfig/lexer.lex.o
  HOSTCC  scripts/kconfig/menu.o
  HOSTCC  scripts/kconfig/parser.tab.o
  HOSTCC  scripts/kconfig/preprocess.o
  HOSTCC  scripts/kconfig/symbol.o
  HOSTCC  scripts/kconfig/util.o
  HOSTLD  scripts/kconfig/conf
#
# configuration written to .config
#
```

We create a `kconfig` file with the options we want to enable. An example is the following:

```
CONFIG_64BIT=y
CONFIG_SMP=y
CONFIG_PRINTK=y
CONFIG_PRINTK_TIME=y

CONFIG_PCI=y

# We use an initramfs for busybox with elf binaries in it.
CONFIG_BLK_DEV_INITRD=y
CONFIG_RD_GZIP=y
CONFIG_BINFMT_ELF=y
CONFIG_BINFMT_SCRIPT=y

# This is for /dev file system.
CONFIG_DEVTMPFS=y

# For the power-down button (triggered by qemu's `system_powerdown` command).
CONFIG_INPUT=y
CONFIG_INPUT_EVDEV=y
CONFIG_INPUT_KEYBOARD=y

CONFIG_MODULES=y

CONFIG_KPROBES=n
CONFIG_LTO_NONE=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_EMBEDDED=n
CONFIG_TMPFS=y

CONFIG_RELOCATABLE=y
CONFIG_RANDOMIZE_BASE=y

CONFIG_USERFAULTFD=y
```

<details>

<summary>Explanation of Options</summary>

* `CONFIG_64BIT` - compiles the kernel for 64-bit
* `CONFIG_SMP` - simultaneous multiprocessing; allows the kernel to run on multiple cores
* `CONFIG_PRINTK`, `CONFIG_PRINTK_TIME` - enables log messages and timestamps
* `CONFIG_PCI` - enables support for loading an initial RAM disk
* `CONFIG_RD_GZIP` - enables support for gzip-compressed initrd images
* `CONFIG_BINFMT_ELF` - enables support for executing ELF binaries
* `CONFIG_BINFMT_SCRIPT` - enables executing scripts with a shebang (`#!`) line
* `CONFIG_DEVTMPFS` - Enables automatic creation of device nodes in `/dev` at boot time using devtmpfs
* `CONFIG_INPUT` - enables support for the generic input layer required for input device handling
* `CONFIG_INPUT_EVDEV` - enables support for the event device interface, which provides a unified input event framework
* `CONFIG_INPUT_KEYBOARD` - enables support for keyboards
* `CONFIG_MODULES` - enables support for loading and unloading kernel modules
* `CONFIG_KPROBES` - disables support for kprobes, a kernel-based debugging mechanism. We disable this because ... TODO
* `CONFIG_LTO_NONE` - disables **Link Time Optimization** (LTO) for kernel compilation. This is to [allow better debugging](https://stackoverflow.com/questions/7857601/why-not-always-use-compiler-optimization)&#x20;
* `CONFIG_SERIAL_8250`, `CONFIG_SERIAL_8250_CONSOLE` - TODO
* `CONFIG_EMBEDDED` - disables optimizations/features for embedded systems
* `CONFIG_TMPFS` - enables support for the tmpfs in-memory filesystem
* `CONFIG_RELOCATABLE` - builds a relocatable kernel that can be loaded at different physical addresses
* `CONFIG_RANDOMIZE_BASE` - enables KASLR support
* `CONFIG_USERFAULTFD` - enables support for the `userfaultfd` system call, which allows handling of page faults in user space

</details>

In order to update the minimal `.config` with these options, we use the provided `merge_config.sh` script:

```bash
$ scripts/kconfig/merge_config.sh .config ../kconfig
```

### Building

```bash
$ make -j4
```

That takes a while, but eventually builds a kernel in `arch/x86/boot/bzImage`. This is the same `bzImage` that you get in CTF challenges.

## Kernel Modules

[When we compile kernel modules for our own kernel](writing-a-char-module/#compiling), we use the following `Makefile` structure:

```
all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
```

To compile it for a different kernel, all we do is change the `-C` flag to point to the newly-compiled kernel rather than the system's:

```
all:
    make -C /home/ir0nstone/linux M=$(PWD) modules
```

The module is now compiled for the specific kernel version!

## Booting the Kernel in a Virtual Machine

### References

* [Build the Linux kernel and Busybox and run them on QEMU](https://www.centennialsoftwaresolutions.com/post/Build-the-Linux-kernel-and-Busybox-and-run-on-QEMU)
* [How to Build A Custom Linux Kernel For Qemu (2015 Edition)](https://mgalgs.io/2015/05/16/how-to-build-a-custom-linux-kernel-for-qemu-2015-edition.html)

### Creating the File System and Executables

We now have a minimal kernel `bzImage` and a kernel module that is compiled for it. Now we need to create a minimal VM to run it in.

To do this, we use [`busybox`](https://busybox.net/about.html), an executable that contains tiny versions of most Linux executables. This allows us to have all of the required programs, in as little space as possible.

We will download and extract `busybox`; you can find the latest version [here](https://busybox.net/downloads/).

<pre class="language-bash"><code class="lang-bash"><strong>$ curl https://busybox.net/downloads/busybox-1.36.1.tar.bz2 | tar xjf -
</strong></code></pre>

We also create an output folder for compiled versions.

```bash
$ mkdir busybox_compiled
```

Now compile it statically. We're going to use the `menuconfig` option, so we can make some choices.

```bash
$ cd busybox-1.36.1
$ make O=../busybox_compiled menuconfig
```

Once the menu loads, hit `Enter` on `Settings`. Hit the down arrow key until you reach the option `Build static binary (no shared libs)`. Hit `Space` to select it, and then `Escape` twice to leave. Make sure you choose to save the configuration.

Now, make it with the new options

```bash
$ cd ../busybox_compiled
$ make -j
$ make install
```

Now we make the file system.

```bash
$ cd ..
$ mkdir initramfs
$ cd initramfs
$ mkdir -pv {bin,dev,sbin,etc,proc,sys/kernel/debug,usr/{bin,sbin},lib,lib64,mnt/root,root}
$ cp -av ../busybox_compiled/_install/* .
$ sudo cp -av /dev/{null,console,tty,sda1} dev/
```

The last thing missing is the classic `init` script, which gets run on system load. A provisional one works fine for now:

```bash
#!/bin/sh
 
mount -t proc none /proc
mount -t sysfs none /sys
 
echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
 
exec /bin/sh
```

Make it executable

```bash
$ chmod +x init
```

Finally, we're going to bundle it into a `cpio` archive, which is understood by QEMU.

```bash
find . -not -name *.cpio | cpio -o -H newc > initramfs.cpio
```

{% hint style="warning" %}
* The `-not -name *.cpio` is there to prevent the archive from including itself
* You can even compress the filesystem to a `.cpio.gz` file, which QEMU also recognises
{% endhint %}

### Loading it with QEMU

Put `bzImage` and `initramfs.cpio` into the same folder. Write a short `run.sh` script that loads QEMU:

```bash
#!/bin/sh

qemu-system-x86_64 \
    -kernel bzImage \
    -initrd initramfs.cpio \
    -append "console=ttyS0 quiet loglevel=3 oops=panic" \
    -monitor /dev/null \
    -nographic \
    -no-reboot
```

<details>

<summary>Explanation of Flags</summary>

* `-kernel bzImage` - sets the kernel to be our compiled `bzImage`
* `-initrd initramfs.cpio` - provide the file system
* `-append ...` - basic features; in the future, this flag is also used to set protections
  * `console=ttyS0` - Directs kernel messages to the first serial port (`ttyS0`)
  * `quiet` - Only showing critical messages from the kernel
  * `loglevel=3` - Only show error messages and higher-priority messages
  * `oops=panic` - Make the kernel panic immediately on an **oops** (kernel error)
* `-monitor /dev/null` - Disable the QEMU monitor
* `-nographic` - Disable GUI, operate in headless mode (faster)
* `no-reboot` - Do not automatically restart the VM when encountering a problem (useful for debugging and working out why it crashes, as the crash logs will stay).

</details>

Once we make this executable and run it, we get loaded into a VM!

### User Accounts

Right now, we have a minimal linux kernel we can boot, but if we try and work out who we are, it doesn't act quite as we expect it to:

```
~ # whoami
whoami: unknown uid 0
```

This is because `/etc/passwd` and `/etc/group` don't exist, so we can just create those!

{% code title="/etc/passwd" %}
```
root:x:0:0:root:/root:/bin/sh
user:x:1000:1000:User:/home/user:/bin/sh
```
{% endcode %}

{% code title="/etc/group" %}
```
root:x:0:
user:x:1000:
```
{% endcode %}

### Loading the Kernel Module

The final step is, of course, the loading of the kernel module. I will be using the module from my [Double Fetch](double-fetch.md) section for this step.

First, we copy the `.ko` file to the filesystem root. Then we modify the `init` script to load it, and also set the UID of the loaded shell to `1000` (so we are not root!).

```bash
#!/bin/sh

insmod /double_fetch.ko
mknod /dev/double_fetch c 253 0
chmod 666 /dev/double_fetch

mount -t proc none /proc
mount -t sysfs none /sys

mknod -m 666 /dev/ttyS0 c 4 64

setsid /bin/cttyhack setuidgid 1000 /bin/sh
```

{% hint style="danger" %}
Here I am assuming that the major number of the `double_fetch` module is `253`.

Why am I doing that?

If we load into a shell and run `cat /proc/devices`, we can see that `double_fetch` is loaded with major number `253` every time. I can't find any way to load this in _without_ guessing the major number, so we're sticking with this for now - please get in touch if you find one!
{% endhint %}
