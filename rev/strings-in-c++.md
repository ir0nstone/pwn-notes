# Strings in C++

## Basic Strings

Reversing C++ can be a pain, and part of the reason for that is that in C++ a `std::string` can be dynamically-sized. This means its appearance in memory is more complex than a `char[]` that you would find in C, because `std::string` [actually contains 3 fields](https://shaharmike.com/cpp/std-string/):

* Pointer to the allocated memory (the actual string itself)
* Logical size of string
* Size of allocated memory (which must be bigger than or equal to logical size)

The actual string content is dynamically allocated on the **heap**. As a result, `std::string` looks something like this in memory:

```cpp
class std::string
{
    char* buf;
    size_t len;
    size_t allocated_len;
};
```

This is not necessarily  a _consistent_ implementation, which is why many decompilers don't recognise strings immediately - they can vary between compilers and different versions.

## Small Object Optimization

Decompilers can confuse us even more depending on how they optimise small objects. Simply put, we would prefer to avoid allocating space on the heap unless absolutely necessary, so if the string is short enough, we try to fit it within the `std::string` struct itself. For example:

```cpp
class std::string
{
    char* buf;
    size_t len;
    
    // union is used to store different data types in the same memory location
    // this saves space in case only one of them is necessary 
    union
    {
        size_t allocated_len;
        char local_buf[8];
    }
};
```

In this example, if the string is 8 bytes or less, `local_buf` is used and the string is stored there instead. `buf` will then point at `local_buf`, and no heap allocation is used.

An analysis of different compilers' approaches to Small Object Optimization can be found [here](https://shaharmike.com/cpp/std-string/).
