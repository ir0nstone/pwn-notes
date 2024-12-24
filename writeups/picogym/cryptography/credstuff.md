---
description: >-
  We found a leak of a blackmarket website's login credentials. Can you find the
  password of the user cultiris and successfully decrypt it? Download the leak
  here.
---

# Credstuff

Opening up `usernames.txt` and `passwords.txt` in Pycharm, we see `cultiris` is on line `378` of `usernames.txt` so we go to line `378` of `passwords.txt` and find an encrypted password:

```
cvpbPGS{P7e1S_54I35_71Z3}
```

The `{}` are in place, implying that it's some sort of transposition cipher for the letters. We've done it numerous times, but we try a caesar cipher decode:

```python
from string import ascii_lowercase, ascii_uppercase

enc_flag = 'cvpbPGS{P7e1S_54I35_71Z3}'

for shift in range(26):
    flag = ''

    for c in enc_flag:
        if c in ascii_lowercase:
            flag += ascii_lowercase[(ascii_lowercase.index(c) + shift) % 26]
        elif c in ascii_uppercase:
            flag += ascii_uppercase[(ascii_uppercase.index(c) + shift) % 26]
        else:
            flag += c

    print(flag)

# picoCTF{C7r1F_54V35_71M3}

```

In fact the shift is 13, so it's just a ROT13.
