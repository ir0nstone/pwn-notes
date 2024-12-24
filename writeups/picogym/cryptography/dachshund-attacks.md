---
description: What if d is too small? Connect with nc mercury.picoctf.net 37455.
---

# Dachshund Attacks

We are told $$d$$ is too small, so this is a classic Wiener's Attack. I discuss the technique [here](https://ir0nstone.gitbook.io/crypto/rsa/public-exponent-attacks/wieners-attack), so I won't go over it again. Connecting to the server gives us $$e$$, $$N$$ and $$c$$. I will use SageMath for the continued fractions.

```python
from Crypto.Util.number import long_to_bytes

e = 112754541700690073210034568883976704637179938391109984739882317717493134117274992183187134977340726366735137168283197063242918320349494617964667665047419548553575295453656621241958205285249437600208333153358419149045651177119281187188167703425363227405679672963841306943107073166807574585389125832534066751809
N = 144390361348920501869993938709991886178924525779849244222262670433367312227444944591566139662690206095975554337178767396284003325304590032011497856478923049097805457881081418119675617493053963010551906982495811656212858357088185653656378487033852680537367010991060358788282243207315359582442103359642135446811
c = 121200875764971898969856362104661551030573743599078234011937926996191831804013529938239036069865696197047682885988162602437942341629152031466396781294970679065309433084336383355723998945746263068555929945549034859795066917254742307603845777657499038889879448604171444521283481396818702315095487896851743793699


def get_convergences(N, e):
    frac = continued_fraction(e / N)
    convergences = list()

    for i in range(frac.length()):
        convergences.append((frac.numerator(i), frac.denominator(i)))

    return convergences


def factorises(N, e, numerator, denominator):
    if numerator == 0:
        return None

    if denominator % 2 == 0:  # d must be odd
        return None

    phi = (e * denominator - 1) / numerator

    if int(phi) % 2 != 0:  # phi must be an even whole number
        return None

    x = var('x')
    assume(x, 'integer')
    solutions = solve([x ** 2 - ((N - phi) + 1) * x + N], x)

    if len(solutions) == 2:
        return solutions

    return None


for numerator, denominator in get_convergences(N, e):
    factors = factorises(N, e, numerator, denominator)

    if factors:
        p, q = factors

        if p * q == N:
            phi = (p - 1) * (q - 1)
            d = inverse_mod(e, phi)
            m = pow(c, d, N)
            print(long_to_bytes(m))
            break

# picoCTF{proving_wiener_3878674}

```
