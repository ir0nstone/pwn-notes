---
description: The better way to calculate offsets
---

# De Bruijn Sequences

De Bruijn sequences of order `n` is simply a sequence where no string of `n` characters is repeated. This makes finding the offset until EIP much simpler - we can just pass in a De Bruijn sequence, get the value within EIP and find the **one possible match** within the sequence to calculate the offset. Let's do this on the **ret2win** binary.

### Generating the Pattern

Again, `radare2` comes with a nice command-line tool \(called `ragg2`\) that can generate it for us. Let's create a sequence of length `100`.

```text
$ ragg2 -P 100 -r
AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAh
```

The `-P` specifies the length while `-r` tells it to show ascii bytes rather than hex pairs.

### Using the Pattern

Now we have the pattern, let's just input it in `radare2` when prompted for input, make it crash and then calculate how far along the sequence the EIP is. Simples.

```text
$ r2 -d -A vuln

[0xf7ede0b0]> dc
Overflow me
AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAh
child stopped with signal 11
[+] SIGNAL 11 errno=0 addr=0x41534141 code=1 ret=0
```

The address it crashes on is `0x41534141`; we can use `radare2`'s in-built `wopO` command to work out the offset.

```text
[0x41534141]> wopO 0x41534141
52
```

Awesome - we get the correct value!

We can also be lazy and not copy the value.

```text
[0x41534141]> wopO `dr eip`
52
```

The backticks means the `dr eip` is calculated first, before the `wopO` is run on the result of it.

