#### Introduction
---

The source code and Makefile are provided for compilation. The exploit was written for `Linux 5.4.0` with the following mitigations enabled when compiling the Kernel:
1. `USER_HARDENED_COPY`
2. `SLUB_FREELIST_RANDOMIZATION`
3. `SMAP, KASLR (FG-KASLR), SMEP, KPTI`

The exploit triggered and used a  Heap Overflow to leak kernel addresses and used a kernel AAW to overwrite `core_pattern`. The following is the expected result when the exploit is run.

![exploit](https://i.imgur.com/pmVgqjm.png)

A core file can simply be dumped by triggering a segmentation fault with ulimit set to `ulimit -c unlimited`, for example, using the following `C` code.

```C
#include <stdio.h>
#include <stdlib.h>

int main(){
	__asm(".intel_syntax noprefix; xor rax, rax; call rax; .att_syntax");
	return 0;
}
```
When the  segmentation fault is triggered  `/tmp/bash` is created and where executed this returns a root shell.

![exploit](https://i.imgur.com/YJa6zBH.png)
