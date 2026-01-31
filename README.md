# dump-vdso

## What

Dumps the Linux VDSO page to standard output.

## Who

Written by Geoffrey Thomas as part of [this blog post](https://ldpreload.com/blog/stupid-tricks-at-the-userspace-kernelspace-boundary) and [released](https://ldpreload.com/pages/copyright) into the public domain under CC0.

## Build

Run `make` or just compile it directly with your C compiler, like: `cc dump-vdso.c -o dump-vdso`.

## Run

The raw vDSO data is printed to file vdso.so by default. You can also print just the symbols and their addresses:
    ./dump-vdso    // default save to file vdso.so
    ./dump-vdso -s // just print symbols and addresses
    
## Inspect

Once you've dumped the vDSO, you can inpspect it.

### Show Symbols

    objdump --dynamic-syms vdso.so
    
### Disassemble

    objdump -d vdso.so
