---
description: Flaws with fork()
---

# Forking Processes

Some processes use `fork()` to deal with multiple requests at once, most notably servers.

An interesting side-effect of `fork()` is that memory is copied **exactly**. This means everything is identical - ELF base, libc base, **canaries**.

This "shared" memory is interesting from an attacking point of view as it allows us to do a **byte-by-byte bruteforce**. Simply put, if there is a response from the server when we send a message, we can work out when it crashed. We keep spamming bytes until there's a response. If the server crashes, the byte is wrong. If not, it's correct.

This allows us to bruteforce the RIP one byte at a time, essentially leaking PIE - and the same thing for canaries and RBP. 24 bytes of multithreaded bruteforce, and once you leak all of those you can bypass a canary, get a stack leak from RBP and PIE base from RIP.

I won't be making a binary for this, but you can check out [ippsec's Rope writeup](https://www.youtube.com/watch?v=GTQxZlr5yvE) for HTB - Rope root was this exact technique.

