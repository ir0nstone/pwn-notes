# Basic-Mod2

Again, simply do what it tells you. For information on the inverse modulo a prime, check out [my notes here](https://ir0nstone.gitbook.io/crypto/fundamentals/modular-arithmetic#modular-multiplicative-inverses)!

```python
from string import ascii_lowercase, digits
from Crypto.Util.number import inverse

numbers = [
    268, 413, 438, 313, 426, 337, 272, 188, 392, 338, 77, 332, 139, 113, 92, 239, 247, 120, 419, 72, 295, 190, 131
]

alphabet = ' ' + ascii_lowercase + digits + '_'     # space at front because letters start at index 1!
flag = ''

for n in numbers:
    idx = inverse(n % 41, 41)
    flag += alphabet[idx]

print(flag)

# picoCTF{1nv3r53ly_h4rd_8a05d939}
```
