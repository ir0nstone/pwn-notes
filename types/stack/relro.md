---
description: Relocation Read-Only
---

# RELRO

RELRO is a protection to stop any GOT overwrites from taking place, and it does so very effectively. There are two types of RELRO, which are both easy to understand.

#### Partial RELRO

Partial RELRO simply moves the GOT above the program's variables, meaning you can't overflow **into** the GOT. This, of course, does not prevent format string overwrites.

#### Full RELRO

Full RELRO makes the GOT completely read-only, so even format string exploits cannot overwrite it. This is **not** the default in binaries due to the fact that it can make it take **much** longer to load as it need to resolve all the function addresses at once.

