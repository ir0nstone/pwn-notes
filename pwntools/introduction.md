---
layout: post
title: Introduction to Pwntools
tags: pwn
categories: pwntools
---

# introduction

## Pwntools

Pwntools is an immensely powerful framework used primarily for binary exploitation, but I have also used it for an challenges that require sockets due to how simplified such interactions are with it.

Here we will be using the **python** version of pwntools, though there is also a Ruby version.

## Installation

The installation is as simple as it can be with python.

```python
pip3 install pwntools
```

## Windows

Unfortunately many features of pwntools are not available on Windows as it uses the `_curses` module, which is not available for Windows.

