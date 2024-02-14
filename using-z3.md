---
description: Microsoft's Theorem Prover
---

# Using Z3

## What is Z3?

Z3 is an **SMT Solver**, a program that can test whether a set of conditions can hold or not, and eventually find a valid solution. This is super helpful in the context of reverse engineering, where you sometimes want to find a valid input or reverse engineer a checker function.

## Installing Z3

Follow [these instructions](https://github.com/Z3Prover/z3?tab=readme-ov-file#building-z3-using-make-and-gccclang):

```bash
$ git clone https://github.com/Z3Prover/z3
$ cd z3
$ python3 scripts/mk_make.py
$ cd build
$ make
$ sudo make install
```

Wait for that to compile. Make sure you also install the [Python bindings](https://github.com/Z3Prover/z3?tab=readme-ov-file#python), which allow you to use Z3 from within Python:

```bash
$ pip install z3-solver
```

## Using Z3

Let's take the example of [Hack The Box's Hissss challenge](https://app.hackthebox.com/challenges/hissss). Once you do the whole python decompilation step, you end up with a large `if` statement for the password:

```python
if ord(password[0]) != 48 
    or password[11] != '!' 
    or ord(password[7]) != ord(password[5]) 
    or 143 - ord(password[0]) != ord(password[4]) 
    or ord(password[1]) ^ ord(password[3]) != 30 
    or ord(password[2]) * ord(password[3]) != 5610 
    or password[1] != 'p' 
    or ord(password[6]) - ord(password[8]) != -46 
    or ord(password[6]) ^ ord(password[7]) != 64 
    or ord(password[10]) + ord(password[5]) != 166 
    or ord('n') - ord(password[9]) != 1 
    or password[10] != str(3):
    
    print('Sorry, the password is incorrect.')
else:
    print(f"Well Done! HTB{{{password}}}")
```

So we have a bunch of relations. Some of them are easy - `password[0] == 48`, `password[10] == str(3)`. Some, however, would require some thinking - the different characters are **interrelated** and appear in multiple statements. Sometimes, you might have other relations - for example, `password[4] > 68`.

What we really want is to be able to plug all of this into a program that will solve the system of statements. Enter Z3!

First, set up the solver:

```python
from z3 import *

s = Solver()

password = [BitVec(f'char{i}', 8) for i in range(12)]
```

A `BitVec` is just a binary number. In this case, we are making them `8` bits long (like a character!) and also calling them `char0`, `char1`, etc. Each `charX` is the `X`th character of the flag, so `password` is really an array of characters which are represented in the form of `BitVec` so that Z3 understands them.

Now we add the conditions to the `Solver` object:

```python
s.add(password[0] == 48)
s.add(password[11] == ord('!'))
s.add(password[7] == password[5])
s.add(143 - password[0] == password[4])
s.add(password[1] ^ password[3] == 30)
s.add(password[2] * password[3] == 5610)
s.add(password[1] == ord('p'))
s.add(password[6] - password[8] == -46)
s.add(password[6] ^ password[7] == 64)
s.add(password[10] + password[5] == 166)
s.add(ord('n') - password[9] == 1)
s.add(password[10] == ord('3'))
```

We then grab the solution as well as setting an `answer` array of the correct length to populate:

```python
s.check()            # generate the model if it exists
sol = s.model()      # grab the model  

answer = [0] * 12
```

The values returned by `sol` are not in the simplest form possible - we have to use `.as_long()` and various other methods - but we can extract the values for each index as so:

```python
# for each variable in the SMT
for d in sol:
    # grab the index is represents
    idx = d.name()
    idx = idx.replace("char", "")
    idx = int(idx)

    # grab its value
    val = sol[d].as_long()
    val = chr(val)

    # and set the index in the `answer` string to be the value
    answer[idx] = val
```

Finally, print the answer

```python
answer = ''.join(answer)
print(answer)
```

We get `0p3n_s3sam3!`
