---
description: >-
  Cryptography can be easy, do you know what ROT13 is?
  cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_uJdSftmh}
---

# Mod 26

We are told that the flag is encrypted with ROT13, which is a simple substitution cipher that replaces every character with the character that is 13 spaces along the alphabet. For example, the character `C` would be replaced by a `P`:

<pre><code><strong>ABCDEFGHIJKLMNOPQRSTUVWXYZ
</strong></code></pre>

You can see that `C` is the 3rd index, and `P` is in fact the 16th. But what if we want to encrypt the letter `Y`, at index 25? Well, what we do here is we _loop back to the beginning_; if we do this, the character 13 positions after it is in fact `L`!

Mathematically, we can see that the index that would be position `26` is actually looping back to position `0`, so we add on the `13` and take the remainder **modulo 26**. We can do this easily in Python, ignoring non-letter characters:

```python
from string import ascii_lowercase, ascii_uppercase

enc_flag = r"cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_uJdSftmh}"

flag = ""

for c in enc_flag:
    if c in ascii_lowercase:
        flag += ascii_lowercase[(ascii_lowercase.index(c) + 13) % 26]
    elif c in ascii_uppercase:
        flag += ascii_uppercase[(ascii_uppercase.index(c) + 13) % 26]
    else:
        flag += c

print(flag)

# picoCTF{next_time_I'll_try_2_rounds_of_rot13_hWqFsgzu}

```

