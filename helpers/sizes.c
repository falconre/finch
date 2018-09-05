cat > /tmp/test.c <<EOF

#define __USE_LARGEFILE64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

#define PRINT_SIZEOF(TYPE)\
    printf("sizeof("#TYPE") = %u\n", (unsigned int) sizeof(TYPE));


int main() {
    PRINT_SIZEOF(unsigned long)
    PRINT_SIZEOF(unsigned long long)
    PRINT_SIZEOF(mode_t)
    PRINT_SIZEOF(uid_t)
    PRINT_SIZEOF(gid_t)
    PRINT_SIZEOF(long long)
    PRINT_SIZEOF(time_t)

    struct stat64 stat64;

    printf("stat64.st_dev 0x%x %u\n",   ((uintptr_t) &stat64.st_dev) - ((uintptr_t) &stat64), sizeof(stat64.st_dev));
    printf("stat64.st_ino 0x%x %u\n",   ((uintptr_t) &stat64.st_ino) - ((uintptr_t) &stat64), sizeof(stat64.st_ino));
    printf("stat64.st_nlink 0x%x %u\n", ((uintptr_t) &stat64.st_nlink) - ((uintptr_t) &stat64), sizeof(stat64.st_nlink));
    printf("stat64.st_mode 0x%x %u\n",  ((uintptr_t) &stat64.st_mode) - ((uintptr_t) &stat64), sizeof(stat64.st_mode));
    printf("stat64.st_uid 0x%x %u\n",   ((uintptr_t) &stat64.st_uid) - ((uintptr_t) &stat64), sizeof(stat64.st_uid));
    printf("stat64.st_gid 0x%x %u\n",   ((uintptr_t) &stat64.st_gid) - ((uintptr_t) &stat64), sizeof(stat64.st_gid));
    printf("stat64.st_rdev 0x%x %u\n",  ((uintptr_t) &stat64.st_rdev) - ((uintptr_t) &stat64), sizeof(stat64.st_rdev));
    printf("stat64.st_size 0x%x %u\n",  ((uintptr_t) &stat64.st_size) - ((uintptr_t) &stat64), sizeof(stat64.st_size));
    printf("stat64.st_blksize 0x%x %u\n", ((uintptr_t) &stat64.st_blksize) - ((uintptr_t) &stat64), sizeof(stat64.st_blksize));
    printf("stat64.st_blocks 0x%x %u\n", ((uintptr_t) &stat64.st_blocks) - ((uintptr_t) &stat64), sizeof(stat64.st_blocks));
    printf("stat64.st_atime 0x%x %u\n", ((uintptr_t) &stat64.st_atime) - ((uintptr_t) &stat64), sizeof(stat64.st_atime));
    printf("stat64.st_mtime 0x%x %u\n", ((uintptr_t) &stat64.st_mtime) - ((uintptr_t) &stat64), sizeof(stat64.st_mtime));
    printf("stat64.st_ctime 0x%x %u\n", ((uintptr_t) &stat64.st_ctime) - ((uintptr_t) &stat64), sizeof(stat64.st_ctime));

    struct stat stat;

    printf("stat.st_dev 0x%x %u\n",   ((uintptr_t) &stat.st_dev) - ((uintptr_t) &stat), sizeof(stat.st_dev));
    printf("stat.st_ino 0x%x %u\n",   ((uintptr_t) &stat.st_ino) - ((uintptr_t) &stat), sizeof(stat.st_ino));
    printf("stat.st_nlink 0x%x %u\n", ((uintptr_t) &stat.st_nlink) - ((uintptr_t) &stat), sizeof(stat.st_nlink));
    printf("stat.st_mode 0x%x %u\n",  ((uintptr_t) &stat.st_mode) - ((uintptr_t) &stat), sizeof(stat.st_mode));
    printf("stat.st_uid 0x%x %u\n",   ((uintptr_t) &stat.st_uid) - ((uintptr_t) &stat), sizeof(stat.st_uid));
    printf("stat.st_gid 0x%x %u\n",   ((uintptr_t) &stat.st_gid) - ((uintptr_t) &stat), sizeof(stat.st_gid));
    printf("stat.st_rdev 0x%x %u\n",  ((uintptr_t) &stat.st_rdev) - ((uintptr_t) &stat), sizeof(stat.st_rdev));
    printf("stat.st_size 0x%x %u\n",  ((uintptr_t) &stat.st_size) - ((uintptr_t) &stat), sizeof(stat.st_size));
    printf("stat.st_blksize 0x%x %u\n", ((uintptr_t) &stat.st_blksize) - ((uintptr_t) &stat), sizeof(stat.st_blksize));
    printf("stat.st_blocks 0x%x %u\n", ((uintptr_t) &stat.st_blocks) - ((uintptr_t) &stat), sizeof(stat.st_blocks));
    printf("stat.st_atime 0x%x %u\n", ((uintptr_t) &stat.st_atime) - ((uintptr_t) &stat), sizeof(stat.st_atime));
    printf("stat.st_mtime 0x%x %u\n", ((uintptr_t) &stat.st_mtime) - ((uintptr_t) &stat), sizeof(stat.st_mtime));
    printf("stat.st_ctime 0x%x %u\n", ((uintptr_t) &stat.st_ctime) - ((uintptr_t) &stat), sizeof(stat.st_ctime));

    return 0;
}
EOF
gcc /tmp/test.c -o /tmp/test && qemu-mipsel -L /usr/mipsel-linux-gnu /tmp/test