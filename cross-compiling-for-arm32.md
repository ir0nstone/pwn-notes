---
description: Absolute pain
---

# Cross-Compiling for arm32

## Basic Compilation

Install [GCC multilib](https://stackoverflow.com/questions/54082459/fatal-error-bits-libc-header-start-h-no-such-file-or-directory-while-compili) and the [arm32 cross-platform toolchain](https://askubuntu.com/questions/250696/how-to-cross-compile-for-arm)

```bash
sudo apt-get install gcc-multilib gcc-arm-linux-gnueabihf
```

[Add the `CC` variable to the `Makefile`](https://askubuntu.com/questions/250696/how-to-cross-compile-for-arm) for `gcc`:

```
CC=arm-linux-gnueabihf-gcc
```

### Compiling Libraries (seccomp)

Extra step required. We have to [add the architecture](https://forums.debian.net/viewtopic.php?t=138023), then update to get the packages:

```bash
sudo dpkg --add-architecture armhf
sudo apt-get update 
```

Finally, install `libseccomp-dev` for `armhf`:

<pre class="language-bash"><code class="lang-bash"><strong>sudo apt-get install libseccomp-dev:armhf
</strong></code></pre>
