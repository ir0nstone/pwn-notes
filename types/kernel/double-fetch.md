---
description: The most simple of vulnerabilities
---

# Double-Fetch

A **double-fetch** vulnerability is when data is accessed from userspace multiple times. Because userspace programs will commonly pass parameters in to the kernel as **pointers**, the data can be modified at any time. If it is modified at the exact right time, an attacker could compromise the execution of the kernel.

Let's see it in action.

## A Vulnerable Kernel Module

Let's say we wish to replace the authentication of the kernel with our own module to handle it. The password to all users on this system is `p4ssw0rd`. However, for security purposes, we do not wish to allow anybody to log in as `root` (yes, it's a very specific case, but it helps to make it clear!).

The code below will be the contents of the `read()` function of a kernel. I've removed [the boilerplate code mentioned previously](writing-a-char-module/a-communicatable-char-driver.md), but this is the relevant part.

```c
```
