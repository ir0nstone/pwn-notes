---
description: >-
  We found a brand new type of encryption, can you break the secret code? (Wrap
  with picoCTF{})
  apbopjbobpnjpjnmnnnmnlnbamnpnononpnaaaamnlnkapndnkncamnpapncnbannaapncndnlnpna
  new_caesar.py
---

# New Caesar

So we are given a script `new_caesar.py`, let's analyse it.

```python
LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

[...]

flag = "redacted"
key = "b"
assert all([k in ALPHABET for k in key])
assert len(key) == 1

b16 = b16_encode(flag)
enc = ""
for i, c in enumerate(b16):
	enc += shift(c, key[i % len(key)])
print(enc)
```

So first off we know that the `ALPHABET` is the first 16 letters in the lowercase alphabet. The `key` is one character long, and is also in `ALPHABET`. The flag has `b16_encode()` run on it, and every letter in the result of that is run under `shift()`. To reverse, it, we have to first undo `shift()` and then `b16_encode()`.

```
def b16_encode(plain):
	enc = ""
	for c in plain:
		binary = "{0:08b}".format(ord(c))
		enc += ALPHABET[int(binary[:4], 2)]
		enc += ALPHABET[int(binary[4:], 2)]
	return enc

def shift(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 + t2) % len(ALPHABET)]
```

`shift()` is a very simple function, although the arithmetic looks a bit strange. `t1` is actually the index of `c` in `ALPHABET`, as it grabs the character code and then subtracts off that of `a`. `t2` is the same, but for the key. `t2` is then added as a shift to `t1` and the index in `ALPHABET` is returned, so it's essentially a Caesar with a shift dictated by `k`. We can undo this easily, by subtracting instead of adding:

```python
def unshift(p, k):
    t1 = ord(p) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 - t2) % len(ALPHABET)]
```

As for `b16encode()`, it calculates the 8-bit binary representation of the character code and then splits it into two 4-bit values, which are used as indices in `ALPHABET`. We can undo this too.

```python
def b16_decode(enc):
    enc = [enc[x:x + 2] for x in range(0, len(enc), 2)]        # split into pairs
    dec = ''

    for pair in enc:
        bin1 = ALPHABET.index(pair[0])
        bin2 = ALPHABET.index(pair[1])
        combined = int(bin(bin1)[2:].zfill(4) + bin(bin2)[2:].zfill(4), 2)
        dec += chr(combined)

    return dec
```

{% hint style="info" %}
The `.zfill(4)` ensures that each representation of the two values is 4 bits long, which is very important for parsing it as an 8-bit bniary value at the end!
{% endhint %}

We then just have to brute force for every possible `key` in `ALPHABET`, getting `16` possibilities:

```
ÐÒÓÛßÐ
ÈèËÌËÊÀûÎÍÍÎÏÿûÊÉþÂÉÁûÎþÁÀüÏþÁÂÊÎÏ
íü×üý·×º»º¹¿ê½¼¼½¾îê¹¸í±¸°ê½í°¿ë¾í°±¹½¾
ÜëÆëì¦Æ©ª©¨®Ù¬««¬­ÝÙ¨§Ü §¯Ù¬Ü¯®Ú­Ü¯ ¨¬­
ËÚµÚÛµÈÌÈËÈËÉË
ºÉ¤ÉÊ¤·»·º·º¸º
©¸¸¹svwvu{¦yxxyzª¦ut©}t|¦y©|{§z©|}uyz
§§¨befedjhgghidclckhkjikldhi
qQqTUTSYWVVWXSR[RZWZYXZ[SWX
v`@`CDCBHsFEEFGwsBAvJAIsFvIHtGvIJBFG
et_tu?_23217b54456fb10e908b5e87c6e89156
TcNcd.N!"! &Q$##$%UQ /T(/'Q$T'&R%T'( $%
CR=RS=@D@C@CAC
?202
!001ûþÿþýó.ñððñò".ýü!õüô.ñ!ôó/ò!ôõýñò
/
/ ê
íîíìâàïïàáìëäëãàãâáãäìàá

Process finished with exit code 0

```

The only one that looks right is `et_tu?_23217b54456fb10e908b5e87c6e89156` (given the title), and we submit that as the flag.

Full script:

```python
import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]


def unshift(p, k):
    t1 = ord(p) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 - t2) % len(ALPHABET)]


def b16_decode(enc):
    enc = [enc[x:x + 2] for x in range(0, len(enc), 2)]
    dec = ''

    for pair in enc:
        bin1 = ALPHABET.index(pair[0])
        bin2 = ALPHABET.index(pair[1])
        combined = int(bin(bin1)[2:].zfill(4) + bin(bin2)[2:].zfill(4), 2)
        dec += chr(combined)

    return dec


enc_flag = 'apbopjbobpnjpjnmnnnmnlnbamnpnononpnaaaamnlnkapndnkncamnpapncnbannaapncndnlnpna'

for key in ALPHABET:
    shifted_flag = ''

    for i, p in enumerate(enc_flag):
        shifted_flag += unshift(p, key)

    d = b16_decode(shifted_flag)

    print(d)

# picoCTF{et_tu?_23217b54456fb10e908b5e87c6e89156}
```
