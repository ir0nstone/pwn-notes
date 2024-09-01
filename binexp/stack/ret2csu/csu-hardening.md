# CSU Hardening

As of [glibc 2.34](https://lwn.net/Articles/864920/), the CSU has been hardened to remove the useful gadgets. [This patch](https://sourceware.org/legacy-ml/libc-alpha/2018-06/msg00717.html) is the offendor, and it essentially removes `__libc_csu_init` (as well as a couple other functions) entirely.

Unfortunately, changing this breaks the ABI (application binary interface), meaning that any binaries compiled in this way can **not** run on pre-2.34 glibc versions - which can make things quite annoying for CTF challenges if you have an outdated glibc version. Older compilations, however, **can** work on the newer versions.
