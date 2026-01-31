# dump-vdso

## What

Dumps the Linux VDSO page to standard output. The vDSO (virtual dynamic shared object) is a shared library that the kernel automatically maps into the address space of all user-space applications. It contains implementations of certain system calls that can be executed in user space, which can improve performance by avoiding the overhead of a traditional system call.

## Who

Written by Geoffrey Thomas as part of [this blog post](https://ldpreload.com/blog/stupid-tricks-at-the-userspace-kernelspace-boundary) and [released](https://ldpreload.com/pages/copyright) into the public domain under CC0.

2026-2-1
Modified by mzhan017 to add symbol printing feature.

## Build

Run `make` or just compile it directly with your C compiler, like: `cc dump-vdso.c -o dump-vdso`.

For 32bit, run `gcc -m32 dump-vdso.c -o dump-vdso-32`.

## Run

The raw vDSO data is saved to file `vdso.so` by default. You can also print just the symbols and their addresses:

```bash
./dump-vdso    # default: save to file vdso.so
./dump-vdso -s # just print symbols and addresses
```
### Example of output
32 bit
```bash
mzhan017:/mnt/d/dump-vdso$ ./dump-vdso -s
Name                                     Address      Offset
----                                     -------      ------
__kernel_vsyscall                        0xf7fa1560 0x00000560
__vdso_gettimeofday                      0xf7fa1790 0x00000790
__vdso_clock_getres                      0xf7fa2520 0x00001520
__vdso_clock_gettime64                   0xf7fa2030 0x00001030
__kernel_sigreturn                       0xf7fa1580 0x00000580
__vdso_time                              0xf7fa1b40 0x00000b40
__kernel_rt_sigreturn                    0xf7fa1590 0x00000590
__vdso_clock_gettime                     0xf7fa1b80 0x00000b80
__vdso_getcpu                            0xf7fa25b0 0x000015b0
```
64 bit
```bash
mzhan017:/mnt/d/dump-vdso$ ./dump-vdso -s
Name                                     Address            Offset
----                                     -------            ------
clock_gettime                            0x00007fffc1f8fa70 0x00000a70
__vdso_gettimeofday                      0x00007fffc1f8f7b0 0x000007b0
clock_getres                             0x00007fffc1f8fdd0 0x00000dd0
__vdso_clock_getres                      0x00007fffc1f8fdd0 0x00000dd0
gettimeofday                             0x00007fffc1f8f7b0 0x000007b0
__vdso_time                              0x00007fffc1f8fa40 0x00000a40
__vdso_sgx_enter_enclave                 0x00007fffc1f8fe70 0x00000e70
time                                     0x00007fffc1f8fa40 0x00000a40
__vdso_clock_gettime                     0x00007fffc1f8fa70 0x00000a70
__vdso_getcpu                            0x00007fffc1f8fe40 0x00000e40
getcpu                                   0x00007fffc1f8fe40 0x00000e40
```
    
## Inspect

Once you've dumped the vDSO, you can inpspect it.

### Show Symbols

    objdump --dynamic-syms vdso.so
    
### Disassemble

    objdump -d vdso.so

## User cases need to use vdso.so
### perf
When doing perf record/report the cpu cycles, perf only print the symbol address, but not symbol name. Then we need findout the symbol name 
based on the vdso.so. For example:
```bash
$ perf record -e cycles -a sleep 1
$ perf report
```
The output will be like:
```
# Samples: 1K of event 'cycles'
#
# Overhead  Symbol
# ........  ......
#
    51.06% abc [vdso]   [.] 0x00000000589
    0xf7ee4589
    0
```