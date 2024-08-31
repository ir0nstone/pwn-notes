# Introduction

The kernel is the program at the heart of the Operating System. It is responsible for controlling every aspect of the computer, from the nature of syscalls to the integration between software and hardware. As such, exploiting the kernel can lead to some incredibly dangerous bugs.

In the context of CTFs, Linux kernel exploitation often involves the exploitation of kernel **modules**. This is an integral feature of Linux that allows users to extend the kernel with their own code, adding additional features.

You can find an excellent introduction to Kernel Drivers and Modules by LiveOverflow [here](https://www.youtube.com/watch?v=juGNPLdjLH4), and I recommend it highly.

### Kernel Modules

Kernel Modules are written in C and compiled to a `.ko` \(**K**ernel **O**bject\) format. Most kernel modules are compiled for a specific version kernel version \(which can be checked with `uname -r`, my Xenial Xerus is `4.15.0-128-generic`\). We can load and unload these modules using the `insmod` and `rmmod` commands respectively. Kernel modules are often loaded into `/dev/*` or `/proc/`. There are 3 main module types: **Char**, **Block** and **Network**.

#### Char Modules

_Char_ Modules are deceptively simple. Essentially, you can access them as a **stream of bytes** - just like a file - using syscalls such as `open`. In this way, they're virtually almost dynamic files \(at a super basic level\), as the values read and written can be changed.

Examples of Char modules include `/dev/random`.

{% hint style="info" %}
I'll be using the term _module_ and _device_ interchangeably. As far as I can tell, they are the same, but please let me know if I'm wrong!
{% endhint %}

