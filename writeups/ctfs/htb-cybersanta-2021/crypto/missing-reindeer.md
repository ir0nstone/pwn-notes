---
description: Cube Root Attack
---

# Missing Reindeer

## Contents

In this challenge, we get a `message.eml` file containing an email:

```
Hello Mr Jingles,

We got the reindeer as you requested. There is a problem though. Its nose is so red and bright and makes it very hard to hide him anywhere near north pole. We have moved to a secret location far away. I have encrypted this information with your public key in case you know who is watching.
```

Applications such as Outlook block downloading the file due to it's "malicious nature", but we can open the `.eml` file in VS Code easily and extract two things:

Firstly, there is a `secret.enc` file with base64-encoded ciphertext:

```
Ci95oTkIL85VWrJLVhns1O2vyBeCd0weKp9o3dSY7hQl7CyiIB/D3HaXQ619k0+4FxkVEksPL6j3wLp8HMJAPxeA321RZexR9qwswQv2S6xQ3QFJi6sgvxkN0YnXtLKRYHQ3te1Nzo53gDnbvuR6zWV8fdlOcBoHtKXlVlsqODku2GvkTQ/06x8zOAWgQCKj78V2mkPiSSXf2/qfDp+FEalbOJlILsZMe3NdgjvohpJHN3O5hLfBPdod2v6iSeNxl7eVcpNtwjkhjzUx35SScJDzKuvAv+6DupMrVSLUfcWyvYUyd/l4v01w+8wvPH9l
```

Secondly, there is a `pubkey.der` file containing an RSA public key:

```
-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA5iOXKISx9NcivdXuW+uE
y4R2DC7Q/6/ZPNYDD7INeTCQO9FzHcdMlUojB1MD39cbiFzWbphb91ntF6mF9+fY
N8hXvTGhR9dNomFJKFj6X8+4kjCHjvT//P+S/CkpiTJkVK+1G7erJT/v1bNXv4Om
OfFTIEr8Vijz4CAixpSdwjyxnS/WObbVmHrDMqAd0jtDemd3u5Z/gOUi6UHl+XIW
Cu1Vbbc5ORmAZCKuGn3JsZmW/beykUFHLWgD3/QqcT21esB4/KSNGmhhQj3joS7Z
z6+4MeXWm5LXGWPQIyKMJhLqM0plLEYSH1BdG1pVEiTGn8gjnP4Qk95oCV9xUxWW
ZwIBAw==
-----END PUBLIC KEY-----
```

## Analysing the Public Key

We can easily import the public key in Python and read the values for $$N$$ and $$e$$ using the Pycryptodome:

```python
from Crypto.PublicKey import RSA

with open('pubkey.pem') as f:
    key = RSA.importKey(f.read())

print(key.n)
print(key.e)
```

We can throw $$N$$ into FactorDB to see if the factors are known, but they are not. The more notable observation is that $$e=3$$, which allows us to perform a [**cube root attack**](https://ir0nstone.gitbook.io/crypto/rsa/public-exponent-attacks/small-e) on the ciphertext.

The logic here is simple: because the message $$m$$ is quite short and the public modulus $$N$$ is quite large, a small value of $$e$$ such as $$3$$ may make it such that $$m^e < N$$. This makes the modulus ineffective as $$m^e = m^e \mod N$$ and we can simply take the $$e$$th root of the ciphertext to recover the plaintext.

## Recovering c

We'll use the `gmpy2` `iroot()` function to calculate the cube root:

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from base64 import b64decode
from gmpy2 import iroot

c = b64decode(b'Ci95oTkIL85VWrJLVhns1O2vyBeCd0weKp9o3dSY7hQl7CyiIB/D3HaXQ619k0+4FxkVEksPL6j3wLp8HMJAPxeA321RZexR9qwswQv2S6xQ3QFJi6sgvxkN0YnXtLKRYHQ3te1Nzo53gDnbvuR6zWV8fdlOcBoHtKXlVlsqODku2GvkTQ/06x8zOAWgQCKj78V2mkPiSSXf2/qfDp+FEalbOJlILsZMe3NdgjvohpJHN3O5hLfBPdod2v6iSeNxl7eVcpNtwjkhjzUx35SScJDzKuvAv+6DupMrVSLUfcWyvYUyd/l4v01w+8wvPH9l')
c = bytes_to_long(c)

m = iroot(c, 3)
print(long_to_bytes(m[0]))
```

And bingo bango, we get the flag as `HTB{w34k_3xp0n3n7_ffc896}`.
