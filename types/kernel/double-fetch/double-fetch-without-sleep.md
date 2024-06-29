---
description: Removing the artificial sleep
---

# Double-Fetch without Sleep

In reality, there won't be a 1-second sleep for your race condition to occur. This means we instead have to hope that it occurs in the assembly instructions between the two dereferences!

This will not work every time - in fact, it's quite likely to not work! - so we will instead have **two** loops; one that keeps writing `0` to the ID, and another that writes another value - e.g. `900` - and then calling `write`. Provided they sync up properly, with enough tries it should be possible.

I can't actually get it working on the code from the last kernel module, for unknown reasons. Perhaps the race is too tight. Apologies for that, I am working on finding a fix.
