#### Introduction
---

The source code and Makefile are provided for compilation. The exploit was written for `Linux 5.4.0` with the following mitigations enabled when compiling the Kernel:
1. `USER_HARDENED_COPY`
2. `SLUB_FREELIST_RANDOMIZATION`
3. `SMAP, KASLR (FG-KASLR), SMEP, KPTI`

The exploit triggered and used a  Heap Overflow to leak kernel addresses and used a kernel AAW to overwrite `core_pattern`. The following is the expected result when the exploit is run.

![exploit](https://i.imgur.com/pmVgqjm.png)

