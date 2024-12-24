---
description: >-
  The one time pad can be cryptographically secure, but not when you know the
  key. Can you solve this? We've given you the encrypted flag, key, and a table
  to help UFJKXQZQUNB with the key of SOLVECRYPT
---

# Easy1

The table is simple - the you grab the plaintext character and the corresponding character from the key and cross-reference them to find the ciphertext character. To reverse it, you find the key character and go along the row (or column) until you find the ciphertext character, then you go perpendicular to it to find the corresponding plaintext character. This nets you `CRYPTOISFUN`, so the flag is `picoCTF{CRYPTOISFUN}`.

{% hint style="info" %}
This is actually a Vigenère cipher, so you could also use an online tool to do it for you!
{% endhint %}
