# Challenges in Containers

Sometimes you get challenges provided with a `Dockerfile`. In most cases, it's best to use it, as you can be sure it acts the same locally and remotely.

Unfortunately, that can be rough. There are a few steps. In essence, we want to use `gdbserver` to set up a debug session, then connect to `gdbserver` from our host to leverage the full power of whatever we want to debug with. These steps work for debugging a binary hosted via `socat`.

So, steps below:

## Install

Add some installs to the Dockerfile:

```
RUN apt-get install -y gdb gdbserver
```

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

```
docker exec -it challenge /bin/bash
```

Note that to get a binary started with `socat`, we have to connect to the service first in order to start a process. So, outside the container, connect with `nc`:

```
$ nc localhost 1337
<pwnable binary>
```

Don't end the process. Switch back to the Docker `root` shell:

```
root@096c4ec3bca6:/# ps auxf
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
ctf           21  0.0  0.0  31612  3000 ?        S    11:55   0:00  \_ socat -dd TCP4-LISTEN:1337,fork,reuseaddr EXEC:/home/ctf/challenge,pty,echo=0,raw,iexten=0
ctf           22  0.0  0.0   4528   212 ?        S    11:55   0:00      \_ /home/ctf/challenge
```

Grab the PID of the subprocess, in this case `22`.&#x20;

## Starting GDBserver

Now start a `gdbserver`:

```
gdbserver :9090 --attach 22
```

And on your host you can now connect to it with radare2 or GDB:

```
$ r2 -d gdb://:9090
```

```
$ gdb challenge
(gdb) target remote :9090
Remote debugging using 172.17.0.2:9090
[...]
(gdb)
```

And boom.

Note the issue is that you have to restart gdbserver _every_ time you connect again, and then reconnect with radare2/GDB. Very unfun! Am hoping to streamline it a bit at some point.
