---
description: How about some hide and seek heh? Look at this image here.
---

# HideToSee

Not the most enjoyable challenge. Gives us an image called `atbash.jpg`, but no ciphertext yet. We actually have to use steganography techniques to extract the ciphertext from being embedded in the image, using `steghide`:

<pre class="language-bash"><code class="lang-bash"><strong>$ steghide extract -sf atbash.jpg
</strong></code></pre>

The passphrase is empty. The `encrypted.txt` file that is created has the following:

```
krxlXGU{zgyzhs_xizxp_8z0uvwwx}
```

Based off the filename, we can assume it's an **atbash cipher**, which is essentially a transposition cipher where alphabet is flipped (so `A` goes to `Z`, `B` goes to `Y`, etc).

```
from string import ascii_uppercase, ascii_lowercase

enc = 'krxlXGU{zgyzhs_xizxp_8z0uvwwx}'
dec = ''

for c in enc:
    if c in ascii_uppercase:
        dec += ascii_uppercase[-(ascii_uppercase.index(c)+1)]       # so index 0 transposes to -1, index 1 to -2, etc
    elif c in ascii_lowercase:
        dec += ascii_lowercase[-(ascii_lowercase.index(c)+1)]
    else:
        dec += c

print(dec)

# picoCTF{atbash_crack_8a0feddc}
```
