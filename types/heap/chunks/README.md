# Chunks

## Allocated Chunks

![](../../../.gitbook/assets/image%20%289%29.png)

The chunk has two sections - the **metadata** of the chunk \(information _about_ the chunk\) and the **user data**, where the data is actually stored.

`size` is fairly self-explanatory - it's the overall size of the chunk.

The flags `A`, `M` and `P` have special uses. `P` is the `PREV_INUSE` flag, which is `0` when the previous adjacent chunk \(the chunk ahead\) is free. `M` and `P` are used for more sophisticated heap attacks, so we won't worry about them just yet.

`prev_size` is set if the previous adjacent chunk is **free**, as calculated by `P`. If it is not, the heap _saves space_ and `prev_size` is part of the **previous chunk's user data**. If it is, then `prev_size` stores the size of the previous chunk.

![](../../../.gitbook/assets/image%20%2812%29.png)

## Free Chunks

A free chunk looks a bit different:

![](../../../.gitbook/assets/image%20%2815%29.png)

The first part is the same, but `FD` and `BK` pointers have been added. This is for the purpose of sorting them into **bins**, which we will come onto soon.

