---
description: >-
  Our data got corrupted on the way here. Luckily, nothing got replaced, but
  every block of 3 got scrambled around!
---

# Transposition-Trial

So we are given the data

```
heTfl g as iicpCTo{7F4NRP051N5_16_35P3X51N3_V6E5926A}4
```

And also told that every block of 3 is scrambled the same way. Looking at the first block of 3, is should clearly say `The`, so the order of reading it should be 3rd letter -> 1st letter -> 2nd letter. We make a quick python script to split it into triplets and rearrange:

```python
message = 'heTfl g as iicpCTo{7F4NRP051N5_16_35P3X51N3_V6E5926A}4'

trigrams = [message[x:x+3] for x in range(0, len(message), 3)]

dec = ''

for t in trigrams:
    dec += t[2] + t[0] + t[1]

print(dec)

# The flag is picoCTF{7R4N5P051N6_15_3XP3N51V3_56E6924A}

```
