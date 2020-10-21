# Use-After-Free

Much like the name suggests, this technique involves us _using data once it is freed_. The weakness here is that programmers often wrongly assume that once the chunk is freed it cannot be used and don't bother writing checks to ensure data is not freed. This means it is possible to write data to a free chunk, which is very dangerous.

