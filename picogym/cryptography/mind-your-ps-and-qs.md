---
description: >-
  In RSA, a small e value can be problematic, but what about N? Can you decrypt
  this? values
---

# Mind Your Ps and Qs

This is typical RSA decryption. We are given `n`, `e` and `c`.

{% hint style="info" %}
If you don't know much about RSA, check out [my overview](https://ir0nstone.gitbook.io/crypto/rsa/overview)!
{% endhint %}

All we need are the factors of `N`. Because it's small, we can try and check if the factors are known using [FactorDB](http://factordb.com). And they are! So from here it's just standard RSA:

```python
from Crypto.Util.number import inverse, long_to_bytes

c = 421345306292040663864066688931456845278496274597031632020995583473619804626233684
n = 631371953793368771804570727896887140714495090919073481680274581226742748040342637
e = 65537

p = 1461849912200000206276283741896701133693
q = 431899300006243611356963607089521499045809

phi = (p-1) * (q-1)
d = inverse(e, phi)
m = pow(c, d, n)

print(long_to_bytes(m))

# picoCTF{sma11_N_n0_g0od_55304594}
```
