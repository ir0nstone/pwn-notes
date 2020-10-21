# Other Chunks

#### Top Chunk

At the top of the section of the heap. If more space is required, it moves down and gives the space. If that chunk is then freed, the top chunk moves back down to reclaim the space.

#### Last Remainder Chunk

Sometimes you have no free chunks of an exact size, but rather just larger; this chunk **splits** into two to service the `malloc` request. One part is returned to the user with the desired size, the other becomes the **Last Remainder Chunk**.

