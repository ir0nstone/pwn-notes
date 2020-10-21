# Heap

Still learning :\)

{% hint style="warning" %}
I will be using a Xenial Xerus VM to do all of these challenges. This is due to the lack of protections on glibc 2.23, and also because radare2 doesn't support heap on the glibc version my Parrot VM works on.  


Sometimes, even Xenial Xerus might be too modern for the very basics of the exploits covered. In these situations, we'll be using `LD_PRELOAD` as opposed to Docker images to make things simpler and I will attempt to provide both the libc and the dynamic linker.
{% endhint %}

{% hint style="info" %}
I may use screenshots more with the heap-related stuff within radare2, as the colour scheme really helps when working out what's happening.
{% endhint %}

