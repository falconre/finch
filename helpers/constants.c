#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

#define PRINT_VALUE(XXX) \
    printf(#XXX ": 0x%0llx\n", (unsigned long long) XXX);

int main() {
    PRINT_VALUE(MAP_SHARED)
    PRINT_VALUE(MAP_PRIVATE)
    PRINT_VALUE(MAP_FIXED)
    // PRINT_VALUE(MAP_LOCAL)
    PRINT_VALUE(MAP_ANONYMOUS)
    PRINT_VALUE(O_CREAT)
    PRINT_VALUE(PROT_READ)
    PRINT_VALUE(PROT_WRITE)
    PRINT_VALUE(PROT_EXEC)
    PRINT_VALUE(SEEK_SET)
    PRINT_VALUE(SEEK_CUR)
    PRINT_VALUE(SEEK_END)
    
    return 0;
}