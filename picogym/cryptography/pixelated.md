---
description: >-
  I have these 2 images, can you make a flag out of them? scrambled1.png
  scrambled2.png
---

# Pixelated

As the images are the same dimensions, it makes sense to consider what could be done with the RBG values. Immediately, XOR springs to mind, and we make a quick script to XOR the pixel data:

```python
from PIL import Image

img1 = Image.open("scrambled1.png")
img2 = Image.open("scrambled2.png")

pixels1 = img1.load()
pixels2 = img2.load()

result_img = Image.new("RGB", img1.size)
result_pixels = result_img.load()

for x in range(img1.width):
    for y in range(img1.height):
        r1, g1, b1 = pixels1[x, y]
        r2, g2, b2 = pixels2[x, y]

        xor_r = r1 ^ r2
        xor_g = g1 ^ g2
        xor_b = b1 ^ b2

        result_pixels[x, y] = (xor_r, xor_g, xor_b)

result_img.save("output.png")

```

This came up with an interesting `output.png`, which definitely had the flag in it, but was quite hard to read:

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption><p>Clearly a flag, but hard to read</p></figcaption></figure>

After some trial and error and printing of the values, you notice that pretty much everywhere is pure white. To up the contrast a little, we make all the white into black:

```python
if xor_r == xor_g == xor_b == 255:
    xor_r = xor_g = xor_b = 0
```

And this was enough to spy the flag:

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

```
picoCTF{d562333d}
```
