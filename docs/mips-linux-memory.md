# Notes on memory model

These notes describe the layout of memory when running a MIPS userland linux process:

```
Linked Binaries (from falcon)
    Start at     0x4000_0000
    Increment by 0x0200_0000
    32 linked binaries will top out at 0x6200_0000

    0x4000_0000 - 0x6200_0000

MMAP
    anonymous mmap addresses begin at 0x6800_0000

    0x6800_0000 - 0x7000_0000

BRK
    0x7000_0000 - 0x8000_0000

Symbolic memory
    0x8000_0000 - 0x9000_0000

Stack set by finch/platform/mips/linux
    0xbff0_0000 start of stack
    0xbff0_0010 argv array
    0xbfff_0000 up to 8 argv arguments
    stack will naturally grow down from 0xbff0_0000

    0xbf00_0000 - 0xc000_0000

TLS
    0xc000_0000 512 bytes
```