# Heap Overflow

Heap Overflow, much like a Stack Overflow, involves too much data being written to the heap. This can result in us overwriting data, most importantly **pointers**. Overwriting these pointers can cause user input to be copied to different locations if the program blindly trusts data on the heap.

To introduce this \(it's easier to understand with an example\) I will use two vulnerable binaries from [Protostar](https://exploit-exercises.lains.space/protostar/).

