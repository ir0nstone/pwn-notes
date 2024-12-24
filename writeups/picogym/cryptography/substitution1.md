---
description: >-
  A second message has come in the mail, and it seems almost identical to the
  first one. Maybe the same thing will work again.
---

# Substitution1

Similar to [Substitution0](substitution0.md), this is a substitution cipher but without the key. We could use online tools, but let's think about how we could maybe determine it ourselves.

Firstly, I'm going to put the entire text to lowercase. I will set the alphabet to full underscores, and only fill it in once I know the transposition; the underscores will denote transpositions I do not know. In the transposition step, if the character is not know it prints it lowercase, while the ones I do know are printed uppercase.

```python
alphabet = '---------------------------'
#           ABCDEFGHIJKLMNOPQRSTUVWXYZ

text = '''
SYTe (eakdy tkd sjbyndr yar thjm) jdr j yobr kt skxbnyrd ersndzyo skxbryzyzkc. Skcyreyjcye jdr bdrercyrq gzya j ery kt sajhhrcmre gazsa yrey yarzd sdrjyzwzyo, yrsaczsjh (jcq mkkmhzcm) evzhhe, jcq bdklhrx-ekhwzcm jlzhzyo. Sajhhrcmre nenjhho skwrd j cnxlrd kt sjyrmkdzre, jcq garc ekhwrq, rjsa ozrhqe j eydzcm (sjhhrq j thjm) gazsa ze enlxzyyrq yk jc kchzcr eskdzcm erdwzsr. SYTe jdr j mdrjy gjo yk hrjdc j gzqr jddjo kt skxbnyrd ersndzyo evzhhe zc j ejtr, hrmjh rcwzdkcxrcy, jcq jdr akeyrq jcq bhjorq lo xjco ersndzyo mdknbe jdkncq yar gkdhq tkd tnc jcq bdjsyzsr. Tkd yaze bdklhrx, yar thjm ze: bzskSYT{TD3UN3CSO_4774SV5_4D3_S001_7JJ384LS}
'''.lower()

# we start lowercase, and make capital letters for ones we know

dec = ''

for c in text:
    if c in alphabet:
        dec += ascii_uppercase[alphabet.index(c)]    # if we know the transposition, good
    else:
        dec += c

print(dec)
```

Initially this prints the text out as is. However, let's see the flag at the end:

```
bzskSYT{TD3UN3CSO_4774SV5_4D3_S001_7JJ384LS}
```

We can determine the characters for `p`, `i`, `c`, `o`, `t` and `f` because we know the flag format!

```python
alphabet = '--s--t--z-----kb---y------'
```

Now the plaintext when printed out looks more interesting, as it includes this:

```
PICOCTF{Fd3un3cCoA4774Cv5A4d3AC001A7jj384lC}
```

Let's look at the rest of the text and see what we can determine.

The first word is `CTFe`, implying that is should say `CTFS`, as not much else can follow `CTF`.

Then, later, it says

```
CTFS jRr j mRrjT gjo TO hrjRc j gIqr
```

which looks like it should say `CTFS ARE A ...`, and we can put those letters in too. By this point we have

```python
alphabet = 'j-s-rt--z-----kb-dey------'
```

And leter on the word `PRACTICE` is already decrypted. Now you continue the process, seeing words such as `SERwICE`. We eventually get

```
CTFS (SHORT FOR CAPTURE THE FLAG) ARE A TYPE OF COMPUTER SECURITY COMPETITION. CONTESTANTS ARE PRESENTED WITH A SET OF CHALLENGES WHICH TEST THEIR CREATIVITY, TECHNICAL (AND GOOGLING) SKILLS, AND PROBLEMJSOLVING ABILITY. CHALLENGES USUALLY COVER A NUMBER OF CATEGORIES, AND WHEN SOLVED, EACH YIELDS A STRING (CALLED A FLAG) WHICH IS SUBMITTED TO AN ONLINE SCORING SERVICE. CTFS ARE A GREAT WAY TO LEARN A WIDE ARRAY OF COMPUTER SECURITY SKILLS IN A SAFE, LEGAL ENVIRONMENT, AND ARE HOSTED AND PLAYED BY MANY SECURITY GROUPS AROUND THE WORLD FOR FUN AND PRACTICE. FOR THIS PROBLEM, THE FLAG IS: PICOCTF{FR3QU3NCY_4774CK5_4R3_C001_7AA384BC}
```

With the key

```python
alphabet = 'jlsqrtmaz-vhxckbudeynwg-o-'
```

Note some letters are missing. The script currently looks like this:

```python
from string import ascii_uppercase, ascii_lowercase

alphabet = 'jlsqrtmaz-vhxckbudeynwg-o-'
#           ABCDEFGHIJKLMNOPQRSTUVWXYZ

text = '''
SYTe (eakdy tkd sjbyndr yar thjm) jdr j yobr kt skxbnyrd ersndzyo skxbryzyzkc. Skcyreyjcye jdr bdrercyrq gzya j ery kt sajhhrcmre gazsa yrey yarzd sdrjyzwzyo, yrsaczsjh (jcq mkkmhzcm) evzhhe, jcq bdklhrx-ekhwzcm jlzhzyo. Sajhhrcmre nenjhho skwrd j cnxlrd kt sjyrmkdzre, jcq garc ekhwrq, rjsa ozrhqe j eydzcm (sjhhrq j thjm) gazsa ze enlxzyyrq yk jc kchzcr eskdzcm erdwzsr. SYTe jdr j mdrjy gjo yk hrjdc j gzqr jddjo kt skxbnyrd ersndzyo evzhhe zc j ejtr, hrmjh rcwzdkcxrcy, jcq jdr akeyrq jcq bhjorq lo xjco ersndzyo mdknbe jdkncq yar gkdhq tkd tnc jcq bdjsyzsr. Tkd yaze bdklhrx, yar thjm ze: bzskSYT{TD3UN3CSO_4774SV5_4D3_S001_7JJ384LS}
'''.lower()

# we start lowercase, and make capital letters for ones we know

dec = ''

for c in text:
    if c in alphabet:
        dec += ascii_uppercase[alphabet.index(c)]
    else:
        dec += c

print(dec)
```

Now we're gonna reuse the one from [Substitution0](substitution0.md) to transpose it for us (with a couple of minor modifications):

```python
from string import ascii_uppercase, ascii_lowercase

alphabet = 'jlsqrtmaz-vhxckbudeynwg-o-'

text = '''
SYTe (eakdy tkd sjbyndr yar thjm) jdr j yobr kt skxbnyrd ersndzyo skxbryzyzkc. Skcyreyjcye jdr bdrercyrq gzya j ery kt sajhhrcmre gazsa yrey yarzd sdrjyzwzyo, yrsaczsjh (jcq mkkmhzcm) evzhhe, jcq bdklhrx-ekhwzcm jlzhzyo. Sajhhrcmre nenjhho skwrd j cnxlrd kt sjyrmkdzre, jcq garc ekhwrq, rjsa ozrhqe j eydzcm (sjhhrq j thjm) gazsa ze enlxzyyrq yk jc kchzcr eskdzcm erdwzsr. SYTe jdr j mdrjy gjo yk hrjdc j gzqr jddjo kt skxbnyrd ersndzyo evzhhe zc j ejtr, hrmjh rcwzdkcxrcy, jcq jdr akeyrq jcq bhjorq lo xjco ersndzyo mdknbe jdkncq yar gkdhq tkd tnc jcq bdjsyzsr. Tkd yaze bdklhrx, yar thjm ze: bzskSYT{TD3UN3CSO_4774SV5_4D3_S001_7JJ384LS}
'''

dec = ''

for c in text:
    if c in ascii_uppercase:
        dec += ascii_uppercase[alphabet.index(c.lower())]
    elif c in ascii_lowercase:
        dec += ascii_lowercase[alphabet.index(c)]
    else:
        dec += c

print(dec)

# picoCTF{FR3QU3NCY_4774CK5_4R3_C001_7AA384BC}
```
