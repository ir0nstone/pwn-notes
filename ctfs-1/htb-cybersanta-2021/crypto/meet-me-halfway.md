---
description: Meet-in-the-middle attack on AES
---

# Meet Me Halfway

## Contents

We are given `challenge.py`, which does the following:

* Creates two keys
  * Key1 is `cyb3rXm45!@#` + 4 random bytes from `0123456789abcdef`
  * Key2 is 4 random bytes from `0123456789abcdef` + `cyb3rXm45!@#`
* Encrypts the flag with Key1 using AES-ECB
* Encrypts the _encrypted_ flag with Key2 using AES-ECB

We can use a **meet-in-the-middle** attack to retreive both keys. The logic here is simple. Firstly, there are `16` possible characters for each of the 4 random bytes, which is easily bruteforceable     ($$16^4$$).

We can also encrypt a given input and get the result - I choose to send `12345678` as the hex-encoded plaintext and receive . For these keys, the encrypted flag is given as:

```
43badc9cfb6198e97e5c0085eba941043982169877c2ec51995b5527d32244ebf3af4453e73408786a9eb39cd7fbb731afd940617e7ad1484ac017a7c0c3798cdb4a96ed96e816cf2a09fd4b39715064d0bba8bbf37e5d713f0af6a850985644
```

## The Attack

Now we have a known plaintext and ciphertext, we can use both one after the other and bruteforce possible keys. Note that the encryption looks like this:

![The Encryption Method](<../../../.gitbook/assets/double\_aes (1).png>)

We do not know what the intermediate value `x` is, but we can use brute force to calculate it by

* Looping through all possibilities for `key1` and saving the encrypted version of `12345678`
* Looping through all possibilities for `key2` and saving the **decryption** of `449e2eb...`
* Finding the intersection between the encryption with `key1` and the decryption with `key2`

Once we find this intersection, we can use that to work back and calculate `key1` and `key2`, which we can then utilise to decrypt the flag.

## Solve Script

```python
from itertools import permutations

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


key_start = b'cyb3rXm45!@#'
alphabet = b'0123456789abcdef'

enc_flag = bytes.fromhex('43badc9cfb6198e97e5c0085eba941043982169877c2ec51995b5527d32244ebf3af4453e73408786a9eb39cd7fbb731afd940617e7ad1484ac017a7c0c3798cdb4a96ed96e816cf2a09fd4b39715064d0bba8bbf37e5d713f0af6a850985644')

known_text = pad(bytes.fromhex("12345678"), 16)
known_ciphertext = bytes.fromhex('449e2eb3a7f793184ef41a8042739307')

# brute all encryptions
encryption_table = {}           # key : value -> encryption result : key

for key in permutations(alphabet, 4):
    key = key_start + bytes(key)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_custom = cipher.encrypt(known_text)
    encryption_table[encrypted_custom] = key


# brute all decryptions
decryption_table = {}           # key : value -> decryption result : key

for key in permutations(alphabet, 4):
    key = bytes(key) + key_start
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_custom = cipher.decrypt(known_ciphertext)
    decryption_table[decrypted_custom] = key


# find the intersection between the keys of decryption_table and encryption_table
# if there is an intersection, we can cross-reference the AES key we used
encryption_table_set = set(encryption_table.keys())
decryption_table_set = set(decryption_table.keys())

intersection = encryption_table_set.intersection(decryption_table_set).pop()
encryption_key = encryption_table[intersection]     # set the encryption key now we know which it is
decryption_key = decryption_table[intersection]     # set the decryption key now we know which it is

# now decrypt flag_enc twice
cipher1 = AES.new(encryption_key, AES.MODE_ECB)
cipher2 = AES.new(decryption_key, AES.MODE_ECB)

flag = cipher2.decrypt(enc_flag)
flag = cipher1.decrypt(flag).decode().strip()

print(flag)
```

And we get the flag as `HTB{m337_m3_1n_7h3_m1ddl3_0f_3ncryp710n}`!
