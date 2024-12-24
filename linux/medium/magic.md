---
description: SQL injection, PHP reverse shell upload, mysqldump and PATH injection
---

# Magic

## Enumeration

As always, let's start with an `nmap`:

```
$ sudo nmap -sS -n -p- -sV -sC -oN depth.nmp 10.10.10.185

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
|_  256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Magic Portfolio
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only ports `22` and `80`. Add `magic.htb` to your `/etc/hosts` and let's check out the website.

### HTTP

![The Main Page](<../../.gitbook/assets/image (32).png>)

There's definitely a lot going on. By analysing the source we can see some images are in the `images/uploads/` folder, which is useful for later. Let's click the `Login` button at the bottom left.

&#x20;

![](<../../.gitbook/assets/image (42).png>)

First thing's first, let's try the default `admin:admin`. We get told it's invalid.

Now we can mess with the input to test for SQL injection. Tampering with a payload such as `'<>:32;4#::!@$":'` doesn't tell us it's invalid; perhaps it's having an affect?

If we try a basic payload such as `admin'#`, what happens? The logic here is it logs in with the username `admin` and comments out the password check to always successfully log us in, essentially making it

```sql
SELECT * FROM users WHERE username = 'admin'#' AND PASSWORD = ''
```

![SQL Injection Check](<../../.gitbook/assets/image (14).png>)

![The Next Page](<../../.gitbook/assets/image (20).png>)

Success!
