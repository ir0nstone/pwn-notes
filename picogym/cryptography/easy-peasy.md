---
description: >-
  A one-time pad is unbreakable, but can you manage to recover the flag? (Wrap
  with picoCTF{}) nc mercury.picoctf.net 11188 otp.py
---

# Easy Peasy

We are given a script `otp.py` and a remote service that serves the script. Let's analyse what it does.

It seems to first start up the process, then it loops an `encrypt()` function:

```python
print("******************Welcome to our OTP implementation!******************")
c = startup(0)
while c >= 0:
	c = encrypt(c)
```

`startup()` has a short process:

<pre class="language-python"><code class="lang-python">KEY_FILE = "key"
KEY_LEN = 50000
FLAG_FILE = "flag"
<strong>
</strong><strong>def startup(key_location):
</strong>	flag = open(FLAG_FILE).read()
	kf = open(KEY_FILE, "rb").read()

	start = key_location
	stop = key_location + len(flag)

	key = kf[start:stop]
	key_location = stop

	result = list(map(lambda p, k: "{:02x}".format(ord(p) ^ k), flag, key))
	print("This is the encrypted flag!\n{}\n".format("".join(result)))

	return key_location
</code></pre>

So, it will read the flag from the file `flag` and the key from the file `key`. It will then grab the first `len(flag)` bytes of `key`.

Note this line:

```python
result = list(map(lambda p, k: "{:02x}".format(ord(p) ^ k), flag, key))
```

is actually just an XOR operation that returns the result as a hex string. As such, it seems to use the bytes of `key` as a one-time-pad, XORing it with the `flag` and returning us the result.

Now let's move on to `encrypt()`:

```python
def encrypt(key_location):
	ui = input("What data would you like to encrypt? ").rstrip()
	if len(ui) == 0 or len(ui) > KEY_LEN:
		return -1

	start = key_location
	stop = key_location + len(ui)

	kf = open(KEY_FILE, "rb").read()

	if stop >= KEY_LEN:
		stop = stop % KEY_LEN
		key = kf[start:] + kf[:stop]
	else:
	key = kf[start:stop]
	key_location = stop

	result = list(map(lambda p, k: "{:02x}".format(ord(p) ^ k), ui, key))

	print("Here ya go!\n{}\n".format("".join(result)))

	return key_location
```

`encrypt()` does the same kind of thing, except with our input! The only difference is here:

```python
if stop >= KEY_LEN:
	stop = stop % KEY_LEN
	key = kf[start:] + kf[:stop]
else:
	key = kf[start:stop]
```

The end point will be looped around to the start point, so once the first `KEY_LEN` bytes of the key file are used it will loop back around and start from the beginning. This makes it possible for us to gain the same OTP twice!

I'm going to use `pwntools` for this process. First we grab the encrypted flag:

```python
from pwn import *

KEY_LEN = 50000

p = remote("mercury.picoctf.net", 11188)

p.recvuntil(b"flag!\n")
enc_flag = p.recvline().strip()
enc_flag_len = len(enc_flag) // 2       # 32
```

Now I will feed a string of length `KEY_LEN - enc_flag_len` into the `encrypt()` function. Why? This will make the `stop` exactly `50000`, meaning the next encryption will have a `start` of `0` again, generating the same OTP as it did for the original flag! Now because XOR is a **involution** - it _undoes itself_ - we can send back the encrypted flag and it will undo the original XOR, returning us the flag!

{% hint style="warning" %}
Be careful that you decode the hex encoding and send the raw bytes!
{% endhint %}

```python
to_enc = b"A" * (KEY_LEN-enc_flag_len)
p.sendlineafter(b"encrypt? ", to_enc)

# now enc flag...
p.sendlineafter(b"encrypt? ", bytes.fromhex(enc_flag.decode()))
p.recvline()
flag = p.recvline().strip()

print(b"picoCTF{" + bytes.fromhex(flag.decode()) + b"}")
```

The full script is as follows:

```python
from pwn import *

KEY_LEN = 50000

p = remote("mercury.picoctf.net", 11188)

p.recvuntil(b"flag!\n")
enc_flag = p.recvline().strip()
enc_flag_len = len(enc_flag) // 2       # 32

to_enc = b"A" * (KEY_LEN-enc_flag_len)
p.sendlineafter(b"encrypt? ", to_enc)

# now enc flag...
p.sendlineafter(b"encrypt? ", bytes.fromhex(enc_flag.decode()))
p.recvline()
flag = p.recvline().strip()

print(b"picoCTF{" + bytes.fromhex(flag.decode()) + b"}")

# picoCTF{7904ff830f1c5bba8f763707247ba3e1}
```
