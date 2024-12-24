---
description: Can you decrypt this message?
---

# Vigenere

So the hint is that the message is encrypted with a Vigenere cipher using the key `CYLAB`. Sure we could use an [online tool](https://www.dcode.fr/vigenere-cipher), but how about in python?

The way a vigenere cipher works is that the letters in the key are converted into integers based into their position in the alphabet, with `0` being `a` and `25` being `z`. Those values are then used as shift values for a per-letter caesar cipher - so in the case of `CYLAB`, the first value is `3` and the second is `24`. Given the encrypted flag:

```
rgnoDVD{O0NU_WQ3_G1G3O3T3_A1AH3S_2951c89f}
```

We then know that `r` is the plaintext letter shifted over by `3` and `g` is the plaintext letter shifted over by `24` (and looped around, in the same way a caesar cipher is). To this end, we can make a quick script:

```python
from string import ascii_uppercase, ascii_lowercase

def shift(chr, k):
    # get an integer shift from a letter
    k_int = ascii_lowercase.index(k.lower())

    if chr in ascii_uppercase:
        return ascii_uppercase[(ascii_uppercase.index(chr) - k_int) % 26]
    else:
        return ascii_lowercase[(ascii_lowercase.index(chr) - k_int) % 26]


message = 'rgnoDVD{O0NU_WQ3_G1G3O3T3_A1AH3S_2951c89f}'
key = 'CYLAB' * 10

dec = ''

for m, k in zip(message, key):
    if m in ascii_uppercase or m in ascii_lowercase:
        dec += shift(m, k)
    else:
        dec += m

print(dec)
```

We get the output

```
picoCTF{O0LW_WP3_V1F3Q3T3_C1AG3U_2951r89d}
```

Which isn't quite the flag. Evidently, it's working.

After a lot of trial and error, it turns out that the problem is that we are looping throuhg them at the same pace, but in reality the key isn't even being incremented on the non-letter characters (for example the `L` in the `key` aligns with `{` in the `message`, nothing is done because it's not a character, but the loop still goes on to the next key character for the next decryption). In essence, we have to just stop the key from looping on those characters:

```python
from string import ascii_uppercase, ascii_lowercase

def shift(chr, k):
    # get an integer shift from a letter
    k_int = ascii_lowercase.index(k.lower())

    if chr in ascii_uppercase:
        return ascii_uppercase[(ascii_uppercase.index(chr) - k_int) % 26]
    else:
        return ascii_lowercase[(ascii_lowercase.index(chr) - k_int) % 26]


message = 'rgnoDVD{O0NU_WQ3_G1G3O3T3_A1AH3S_2951c89f}'
key = 'CYLAB'

dec = ''

i = 0
for m in message:
    if m in ascii_uppercase or m in ascii_lowercase:
        dec += shift(m, key[i])
        i = (i+1) % 5
    else:
        dec += m

print(dec)

# picoCTF{D0NT_US3_V1G3N3R3_C1PH3R_2951a89h}
```
