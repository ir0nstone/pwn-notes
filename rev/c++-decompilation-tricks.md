---
description: How decompilers do stuff
---

# C++ Decompilation Tricks

These tricks include notes for Binary Ninja, but IDA looks similar (and I'm sure GHidra does too).

Example code:

```cpp
char rax_3 = *std::vector<uint8_t>::operator[](&vector, sx.q(j))
*std::vector<uint8_t>::operator[](&vector, sx.q(j)) = *std::string::operator[](arg1, other: j) ^ rax_3
```

Looks really bizarre and overwhelming, but look at the words. `std::vector<uint8_t>::operator[]` literally means the operator `[]`, the subscript operator. It wants the subscript of the first parameter, with the second parameter being the argument. So

```cpp
std::vector<uint8_t>::operator[](&vector, sx.q(j))
```

Is really just

```cpp
vector[j]
```

Also, if it doesn't make sense, change types to add extra arguments! Detection is pretty trash, and it might help a lot.

A non-exhaustive list is:

<table data-full-width="true"><thead><tr><th>Decompilation</th><th>Meaning</th><th>Parameter(s)</th></tr></thead><tbody><tr><td><code>std::T::~T</code></td><td>Destructor of class <code>T</code></td><td><code>T*</code></td></tr><tr><td><code>std::vector&#x3C;T>::operator[](&#x26;vector, sx.q(j))</code></td><td><code>vector[j]</code></td><td><code>T*</code>, <code>int64_t</code></td></tr><tr><td></td><td></td><td></td></tr></tbody></table>
