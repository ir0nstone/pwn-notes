# Xmas Spirit

## Contents

We get given `challenge.py` and `encrypted.bin`. Analysing `challenge.py`:

```python
import random
from math import gcd

def encrypt(dt):
	mod = 256
	while True:
		a = random.randint(1, mod)
		if gcd(a, mod) == 1:
			break
	b = random.randint(1, mod)

	res = b''
	for byte in dt:
		enc = (a * byte + b) % mod
		res += bytes([enc])
	return res


dt = open('letter.pdf', 'rb').read()

res = encrypt(dt)

f = open('encrypted.bin', 'wb')
f.write(res)
f.close()
```

It calculates two random values, $$a$$ and $$b$$. For every byte $$k$$ in the plaintext file, it then calculates

$$
ak + b \mod 256
$$

And appends the result of that as the encrypted character in `encrypted.bin`.

## Analysis

The plaintext file appears to be `letter.pdf`, and using this we can work out the values of $$a$$ and $$b$$ because we know the first 4 bytes of every PDF file are `%PDF`. We can extract the first two bytes of `encrypted.bin` and compare to the expected two bytes:

```python
with open('encrypted.bin', 'rb') as f:
    res = f.read()

print(res[0])
print(res[1])
print(ord('%'))
print(ord('P'))
```

Gives us

```python
13
112
37
80
```

So we can form two equations here using this information:



$$
a \cdot 37 + b \equiv 13 \mod 256 \\
a \cdot 80 + b \equiv 112 \mod 256
$$

We subtract (2) from (1) to get that

$$
43a \equiv 99 \mod 256
$$

And we can multiply both sides by the **modular multiplicative inverse** of 43, i.e. $$43^{-1} \mod 256$$, which is $$131$$, to get that

$$
a \equiv 99 \cdot 131 \equiv 169 \mod 256
$$

And then we can calculate $$b$$:

$$
b \equiv 13 - 169 * 37 \equiv 160 \mod 256
$$

## Solution

So now we have the values for $$a$$ and $$b$$, it's simply a matter of going byte-by-byte and reversing it. I created a simple Sage script to do this with me, and it took a bit of time to run but eventually got the flag.

```python
with open('encrypted.bin', 'rb') as f:
    res = f.read()


final = b''


R = IntegerModRing(256)

for char in res:
    b = bytes([ (R(char) - R(160)) / R(169) ])
    print(b.decode('latin-1'), end='')
    final += b

with open('answer.pdf', 'wb') as f:
    f.write(final)
```

And the resulting PDF has the flag `HTB{4ff1n3_c1ph3r_15_51mpl3_m47h5}` within.
