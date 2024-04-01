Introduction
---

The source code and Makefile are provided for compilation. The exploit was written for `Linux 5.13.0` with the following mitigations disabled when building the Kernel. 
1. `USER_HARDENED_COPY`: This allowed us to trigger the Heap Buffer Overflow despite writing bytes greater that the buffer allocated via `kmalloc`
2. `SLUB_FREELIST_RANDOMIZATION`
3. All the other mitigations `SMAP, KASLR (FG-KASLR), SMEP, KPTI` we enabled by default. 


