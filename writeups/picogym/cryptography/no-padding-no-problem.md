---
description: >-
  Oracles can be your best friend, they will decrypt anything, except the flag's
  ciphertext. How will you break it? Connect with nc mercury.picoctf.net 10333
---

# No Padding, No Problem

Upon connecting, we get the values of $$N$$ and $$e$$ as well as the encrypted ciphertext $$c$$ that represents the flag. We then have a decryption oracle, which can decrypt anything except for the flag.

Note that the ciphertext is decrypted as follows:

$$
m \equiv c^d \mod N
$$

If we ask to decrypt $$-c$$ instead, we get

$$
m \equiv (-c)^d \equiv -c^d \mod N
$$

Note the last congruence is because $$d$$ is odd, so $$(-1)^d = -1$$.

This means that if we pass in the negative of $$c$$, we can get the negative of the decryption!

```
N = 64225632402784743608151428388331019007158039700441403609620876723228303996217136829769322251101831115510439457268097599588978823846061420515078072743333076016253031234729517071419809456539618743788851473244412318432363995783182914809195026673348987512316519371501063936603604905070428868194818209957885002651
R = IntegerModRing(N) 
c = R(23961525860638788006091919862301366730415613260613078904461027043559403510831473561860834624403033454974614369313881141911510211211764847671996788759608002057996932820692709010900418723347410147858586280735791816478632919784849715797867137711835451159040091442311708166252069010315360215005284477472628144578)
print(-c)

# send it back, get result
negative_m = R(64225632402784743608151428388331019007158039700441403609620876723228303996217136829769322251101831115510439457268097599588978823846061420515078072743333076016253031234729517071419809456249343713593001433770955700064908110713217165957916949916605267065613204854099704669280835867601177422810391570120236404254)
long_to_bytes(-m)

# picoCTF{m4yb3_Th0se_m3s54g3s_4r3_difurrent_1772735}
```

{% hint style="info" %}
There are other ways to do it too - you could calculate $$2^{65537} \mod N$$ and multiply $$c$$ by that, which would yield you $$2c$$ after decryption, and you'd just need to halve it, [as described in this writeup](https://github.com/Dvd848/CTFs/blob/master/2021\_picoCTF/No\_Padding\_No\_Problem.md).
{% endhint %}
