#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#define OFFSET_STEP 4096

void scan_file(const char *filepath, bool reverse) {
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror(filepath);
        return;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        perror("fstat");
        close(fd);
        return;
    }

    off_t start, end, step;
    if (reverse) {
        start = st.st_size - 1;
        end = start % OFFSET_STEP;
        step = -OFFSET_STEP;
    } else {
        start = 0;
        end = st.st_size & -OFFSET_STEP;
        step = OFFSET_STEP;
    }

    unsigned char buf;
    for (off_t offset = start; offset != end; offset += step) {
        if (lseek(fd, offset, SEEK_SET) == (off_t)-1) {
            perror("lseek");
            break;
        }
        if (read(fd, &buf, 1) != 1) {
            // Could be EOF or error
            break;
        }
        // For benchmarking, we just read the byte
    }

    close(fd);
}

void scan_dir(const char *dirpath, bool reverse) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        perror(dirpath);
        return;
    }

    struct dirent *entry;
    char filepath[4096];
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            // Skip . and ..
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            // Recursively scan subdirectories
            snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);
            scan_dir(filepath, reverse);
            continue;
        }
        if (entry->d_type != DT_REG)
            continue; // Only regular files

        snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);
        scan_file(filepath, reverse);
    }

    closedir(dir);
}

const char *usage = "Usage: scan [-r] <directory> <page_index> <syncpipe>\n";
char syncpipe_buf[256];
int syncpipe_buf_len = 0;

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "%s", usage);
        return 1;
    }

    bool reverse = false;
    char* dirpath = NULL;
    char* syncpipe_name = NULL;
    if (argc >= 4 && strcmp(argv[1], "-r") == 0) {
        reverse = true;
        dirpath = argv[2];
        syncpipe_name = argv[4];
    } else {
        dirpath = argv[1];
        syncpipe_name = argv[3];
    }
    strncpy(syncpipe_buf, syncpipe_name, sizeof(syncpipe_buf) - 1);
    syncpipe_buf[sizeof(syncpipe_buf) - 1] = '\0';
    syncpipe_buf_len = strlen(syncpipe_buf);
    if (syncpipe_buf_len + 4 >= sizeof(syncpipe_buf)) {
        fprintf(stderr, "Sync pipe name too long\n");
        return 1;
    }

    // write pid to <syncpipe_name>.bwd
    strcpy(syncpipe_buf + syncpipe_buf_len, ".bwd");
    int bwd_fd = open(syncpipe_buf, O_WRONLY);
    if (bwd_fd < 0) {
        perror(syncpipe_buf);
        return 1;
    }
    char pid_buf[32];
    snprintf(pid_buf, sizeof(pid_buf), "%d", getpid());
    if (write(bwd_fd, pid_buf, strlen(pid_buf)) != (ssize_t)strlen(pid_buf)) {
        perror("write to syncpipe.bwd");
        close(bwd_fd);
        return 1;
    }
    close(bwd_fd);

    // Read from syncpipe to synchronize with the parent process
    strcpy(syncpipe_buf + syncpipe_buf_len, ".fwd");
    int fwd_fd = open(syncpipe_buf, O_RDONLY);
    if (fwd_fd < 0) {
        perror(syncpipe_buf);
        return 1;
    }
    char buf;
    if (read(fwd_fd, &buf, 1) != 1) {
        perror("read from syncpipe");
        close(fwd_fd);
        return 1;
    }
    close(fwd_fd);
    
    scan_dir(dirpath, reverse);
    return 0;
}