#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#define PAGE_SIZE 4096
#define HIT_INDEX 77 // arbitrary page offset to repeatedly hit
#define HIT_COUNT 100

void rephit_file(const char *filepath) {
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

    // if we have enough pages, we can just mmap and repeatedly hit the same page
    long long sum = 0;  // to prevent compiler optimization
    if (st.st_size > HIT_INDEX * PAGE_SIZE) {
        char *map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
        if (map == MAP_FAILED) {
            perror("mmap");
            goto cleanup;
        }
        // don't want prefetching
        int before = HIT_INDEX * PAGE_SIZE;
        int after = (HIT_INDEX + 1) * PAGE_SIZE;
        if (madvise(map, before, MADV_DONTNEED) != 0 ||
            after < st.st_size && madvise(map + after, st.st_size - after, MADV_DONTNEED) != 0) {
            perror("madvise");
            goto cleanup;
        }
        for (int i = 0; i < HIT_COUNT; ++i) {
            volatile char c = map[HIT_INDEX * PAGE_SIZE];
            sum += c; // prevent compiler optimization
            // flush cpu cache to get better resolution (only works on x86-64)
            asm volatile("clflush (%0)" :: "r"(map + HIT_INDEX * PAGE_SIZE));
        }
        cleanup:
        munmap(map, st.st_size);
    }
    close(fd);
}

void rephit_dir(const char *dirpath) {
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
            rephit_dir(filepath);
            continue;
        }
        if (entry->d_type != DT_REG)
            continue; // Only regular files

        snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);
        rephit_file(filepath);
    }

    closedir(dir);
}

const char *usage = "Usage: rephit <directory> <syncpipe>\n";
char syncpipe_buf[256];
int syncpipe_buf_len = 0;

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Error: %s", usage);
        return 1;
    }

    bool reverse = false;
    char* dirpath = argv[1];
    char* syncpipe_name = argv[2];

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
    int fd = open(syncpipe_buf, O_RDONLY);
    if (fd < 0) {
        perror(syncpipe_buf);
        return 1;
    }
    char buf;
    if (read(fd, &buf, 1) != 1) {
        perror("read from syncpipe");
        close(fd);
        return 1;
    }
    close(fd);

    rephit_dir(dirpath);
    return 0;
}