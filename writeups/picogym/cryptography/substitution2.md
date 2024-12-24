---
description: >-
  It seems that another encrypted message has been intercepted. The encryptor
  seems to have learned their lesson though and now there isn't any punctuation!
  Can you still crack the cipher?
---

# Substitution2

This time around, we don't even have spaces or full stops!

```
isnfnnpctitnznfmxhisnfwnxxntimjxctsnascdstushhxuhgqbinftnubfciruhgqnicichktckuxbackdurjnfqmifchimkabturjnfusmxxnkdnisntnuhgqnicichktehubtqfcgmfcxrhktrtingtmagckctifmichkebkamgnkimxtwscusmfnznfrbtnebxmkagmfonimjxntocxxtshwnznfwnjnxcnznisnqfhqnfqbfqhtnhemscdstushhxuhgqbinftnubfciruhgqnicichkctkhihkxrihinmuszmxbmjxntocxxtjbimxthihdnitibankitckinfntinackmkanpucinamjhbiuhgqbinftucnkunanenktcznuhgqnicichktmfnheinkxmjhfchbtmeemcftmkauhgnahwkihfbkkckdusnuoxctitmkanpnubickduhkecdtufcqitheenktnhkisnhisnfsmkactsnmzcxrehubtnahknpqxhfmichkmkacgqfhzctmichkmkaheinksmtnxngnkitheqxmrwnjnxcnznmuhgqnicichkihbusckdhkisnheenktcznnxngnkitheuhgqbinftnubfcirctisnfnehfnmjniinfznscuxnehfinusnzmkdnxctgihtibankitckmgnfcumkscdstushhxtebfisnfwnjnxcnznismimkbkanftimkackdheheenktczninuskcvbntctnttnkicmxehfghbkickdmkneenuicznanenktnmkaismiisnihhxtmkauhkecdbfmichkehubtnkuhbkinfnackanenktcznuhgqnicichktahntkhixnmatibankitihokhwisncfnkngrmtneenuicznxrmtinmusckdisngihmuicznxrisckoxconmkmiimuonfqcuhuiectmkheenktcznxrhfcnkinascdstushhxuhgqbinftnubfciruhgqnicichkismitnnotihdnknfminckinfntickuhgqbinftucnkunmghkdscdstushhxnftinmusckdisngnkhbdsmjhbiuhgqbinftnubfcirihqcvbnisncfubfchtcirghiczmickdisngihnpqxhfnhkisncfhwkmkankmjxckdisngihjniinfanenkaisncfgmusckntisnexmdctqcuhUIE{K6F4G_4K41R515_15_73A10B5_702E03EU}
```

We can use a similar approach to last time, but this time we may have to use frequency analysis (as suggested by the last flag!) and even bi- and trigram analysis. This means finding common letters, or common groupings of 2/3 letters, and comparing it to what would typically occur in a regular english text.

However, first off, there is very clearly a flag at the end:

```
qcuhUIE{K6F4G_4K41R515_15_73A10B5_702E03EU}
```

And we can use the same initial approach as [last time](substitution1.md) and update the alphabet accordingly.

```python
alphabet = '--u--e--c-----hq---i------'
#           ABCDEFGHIJKLMNOPQRSTUVWXYZ
```

I can then see the following string:

```
PnTITIOk
```

so there is a word `P*TITIO*`. According to a [crossword solver](https://www.crosswordsolver.org/solve/p-titio-), that's either `petition` or `petitios`. But ahead of it, there's even more:

```
COgPnTITIOk
```

This looks like `COMPETITION`! Let's throw that in.

After spotting lots more words like `cybersecurity` etc, I get the `alphabet`:

```python
alphabet = 'mjuanedsc-oxgkhqvftibzwpr-'
```

And we use the decrypt again:

```python
from string import ascii_uppercase, ascii_lowercase

alphabet = 'mjuanedsc-oxgkhqvftibzwpr-'

text = 'isnfnnpctitnznfmxhisnfwnxxntimjxctsnascdstushhxuhgqbinftnubfciruhgqnicichktckuxbackdurjnfqmifchimkabturjnfusmxxnkdnisntnuhgqnicichktehubtqfcgmfcxrhktrtingtmagckctifmichkebkamgnkimxtwscusmfnznfrbtnebxmkagmfonimjxntocxxtshwnznfwnjnxcnznisnqfhqnfqbfqhtnhemscdstushhxuhgqbinftnubfciruhgqnicichkctkhihkxrihinmuszmxbmjxntocxxtjbimxthihdnitibankitckinfntinackmkanpucinamjhbiuhgqbinftucnkunanenktcznuhgqnicichktmfnheinkxmjhfchbtmeemcftmkauhgnahwkihfbkkckdusnuoxctitmkanpnubickduhkecdtufcqitheenktnhkisnhisnfsmkactsnmzcxrehubtnahknpqxhfmichkmkacgqfhzctmichkmkaheinksmtnxngnkitheqxmrwnjnxcnznmuhgqnicichkihbusckdhkisnheenktcznnxngnkitheuhgqbinftnubfcirctisnfnehfnmjniinfznscuxnehfinusnzmkdnxctgihtibankitckmgnfcumkscdstushhxtebfisnfwnjnxcnznismimkbkanftimkackdheheenktczninuskcvbntctnttnkicmxehfghbkickdmkneenuicznanenktnmkaismiisnihhxtmkauhkecdbfmichkehubtnkuhbkinfnackanenktcznuhgqnicichktahntkhixnmatibankitihokhwisncfnkngrmtneenuicznxrmtinmusckdisngihmuicznxrisckoxconmkmiimuonfqcuhuiectmkheenktcznxrhfcnkinascdstushhxuhgqbinftnubfciruhgqnicichkismitnnotihdnknfminckinfntickuhgqbinftucnkunmghkdscdstushhxnftinmusckdisngnkhbdsmjhbiuhgqbinftnubfcirihqcvbnisncfubfchtcirghiczmickdisngihnpqxhfnhkisncfhwkmkankmjxckdisngihjniinfanenkaisncfgmusckntisnexmdctqcuhUIE{K6F4G_4K41R515_15_73A10B5_702E03EU}'.lower()
dec = ''

for c in text:
    if c in ascii_uppercase:
        dec += ascii_uppercase[alphabet.index(c.lower())]
    elif c in ascii_lowercase:
        dec += ascii_lowercase[alphabet.index(c)]
    else:
        dec += c

print(dec)

# picoctf{n6r4m_4n41y515_15_73d10u5_702f03fc}
```

As we can see from the flag (and also the hint), [ngram](https://en.wikipedia.org/wiki/N-gram) analysis was the way to go.
