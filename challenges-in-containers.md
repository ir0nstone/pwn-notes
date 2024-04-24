# Challenges in Containers

Sometimes you get challenges provided with a `Dockerfile`. In most cases, it's best to use it, as you can be sure it acts the same locally and remotely.

Unfortunately, that can be rough. There are a few steps. In essence, we want to use `gdbserver` to set up a debug session, then connect to `gdbserver` from our host to leverage the full power of whatever we want to debug with. These steps work for debugging a binary hosted via `socat`.

## Quick Copy

Add:

<pre class="language-docker"><code class="lang-docker">RUN apt-get install -y gdb gdbserver
<strong> -- OR --
</strong>RUN apk add gdb

-p 9090:9090 --cap-add=SYS_PTRACE
</code></pre>

Run:

```bash
docker exec -it challenge /bin/bash
gdbserver :9090 --attach $(pidof challenge)
```

Connect:

```bash
r2 -d gdb://localhost:9090
```

OR

```bash
gdb challenge
target remote :9090
```

## Explanation

### Install

Add some installs to the Dockerfile:

```docker
RUN apt-get install -y gdb gdbserver
```

If the Dockerfile is an alpine image, instead use

```docker
RUN apk add gdb
```

`gdbserver` is automatically installed as part of the package.

## Change Run Command in build\_docker.sh

Add the&#x20;

```
-p 9090:9090 --cap-add=SYS_PTRACE
```

flags to the `docker run ...` command in `build_docker.sh`.

* `-p 9090:9090` binds the internal port `9090` to the external port `9090`, so we can connect to `localhost:9090` for the `gdbserver`
* `--cap-add=SYS_PTRACE` gives the container the capability to `ptrace` a process, which we need for debugging. The alternative is to run it in `--privileged` mode, which is far more unsafe

## Start the Executable and get the PID

Get a shell with `docker exec`:

```bash
docker exec -it challenge /bin/bash
```

Note that to get a binary started with `socat`, we have to connect to the service first in order to start a process. So, outside the container, connect with `nc`:

```bash
$ nc localhost 1337
<pwnable binary>
```

Don't end the process. Switch back to the Docker `root` shell:

```
root@096c4ec3bca6:/# pidof challenge
22
```

Grab the PID of the subprocess, in this case `22`.&#x20;

## Starting GDBserver

Now start a `gdbserver`:

```
gdbserver :9090 --attach 22
```

{% hint style="info" %}
You can combine this into one command:\
`gdbserver :9090 --attach $(pidof challenge)`
{% endhint %}

And on your host you can now connect to it with radare2 or GDB:

```bash
$ r2 -d gdb://localhost:9090
```

```
$ gdb challenge
(gdb) target remote :9090
Remote debugging using 172.17.0.2:9090
[...]
(gdb)
```

And boom.

Note the issue is that you have to restart gdbserver _every_ time you connect again. Don't forget! Maybe there's a better way, but I don't know.

Did try and replace the shell commands with a single `docker exec`, but the `$()` is resolved before it is piped to the Docker:

```bash
$ docker exec -it challenge gdbserver :9090 --attach $(pidof challenge)
Cannot attach to process 7196: No such process (3)
Exiting
```

But when connecting via shell and running, it worked:

```bash
$ docker exec -it challenge /bin/bash
root@e2cd6b6e2e2c:/# gdbserver :9090 --attach $(pidof challenge)
Attached; pid = 201
Listening on port 9090
```

If anybody finds a fix, please let me know!
