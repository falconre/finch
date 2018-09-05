cat > /tmp/test.c <<EOF

#define __USE_LARGEFILE64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE


#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


int main (int argc, char * argv[]) {
    struct stat64 s64;
    int fd;

    if (argc == 1)
        fd = open("/bin/ls", O_RDONLY);
    else
        fd = open(argv[1], O_RDONLY);
    fstat64(fd, &s64);

    uint32_t * u32 = (uint32_t *) &s64;
    unsigned int i;

    for (i = 0; i < 0x20; i++) {
        printf("0x%02x: 0x%08x\n", i * 4, u32[i]);
    }

    close(fd);
}
EOF
mipsel-linux-gnu-gcc /tmp/test.c -o /tmp/test && qemu-mipsel -L /usr/mipsel-linux-gnu /tmp/test
