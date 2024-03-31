Introduction
---

The source code and the make file are provided for compilation. The exploit was written for `Linux 5.13.0` with the following mitigations disabled. 
1. `USER_HARDENED_COPY`: This allowed us to trigger the Heap Buffer Overflow despite the writing bytes greater that the buffer allocated via `kmalloc`
2. `SLUB_FREELIST_RANDOMIZATION`


