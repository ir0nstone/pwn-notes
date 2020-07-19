---
layout: post
tags: pwn
categories: pwntools
---

## Processes
A `process` is the main way you interact with something in pwntools, and starting one is easy.

```python
p = process('./vulnerable_binary')
```
You can also start **remote** processes and connect to sockets using `remote`:

```python
p = remote('my.special.ip', port)
```

## Sending Data to Processes
The power of `pwntools` is incredibly simple communication with your processes.

#### p.send(data)
Sends `data` to the process. Data can either be a `string` or a `bytes-like object` - pwntools handles it all for you.

#### p.sendline(data)
Sends `data` to the process, followed by a **newline character** `\n`. Some programs require the `\n` to take in the input (think about how you need to hit the enter key to send the data with `nc`) while others don't.<br>

`p.sendline(data)` is equivalent to `p.send(data + '\n')`<br>

*Note: An incorrect number of these may cause your exploit to stall when there's nothing wrong with it. This should be the first thing you check. If you're uncertain, use `p.clean()` instead.*

## Receiving Data From Processes

#### p.recv(numb)
Receives `numb` bytes from the process.

#### p.recvuntil(delimiter, drop=False)
Receives all the data until it encounters the `delimiter`, after which it returns the data. If `drop` is `True` then the returned data does not include the `delimiter`.

#### p.recvline(keepends=True)
Essentially equivalent to `p.recvuntil('\n', drop=keepends)`.<br>
Receives up until a `\n` is reached, then returns the data including the `\n` if `keepends` is `True`.

#### p.clean(timeout=0.02)
Receives **all** data for `timeout` seconds and returns it. Another similar function is `p.recvall()`, but this regularly takes far too long to execute so `p.clean()` is much better.

#### Timeout
All receiving functions all contain a `timeout` parameter as well as the other listed ones.<br>
For example, `p.recv(numb=16, timeout=1)` will execute but if `numb` bytes are not received within `timeout` seconds the data is buffered for the next receiving function and an empty string `''` is returned.