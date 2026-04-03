#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#define OFFSET_STEP 4096
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
    if (st.st_size > HIT_INDEX * OFFSET_STEP) {
        char *map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
        if (map == MAP_FAILED) {
            perror("mmap");
            close(fd);
            return;
        }
        for (int i = 0; i < HIT_COUNT; ++i) {
            volatile char c = map[HIT_INDEX * OFFSET_STEP];
            (void)c; // prevent compiler optimization
            // flush cpu cache to get better resolution (only works on x86-64)
            asm volatile("clflush (%0)" :: "r"(map + HIT_INDEX * OFFSET_STEP));
        }
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

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Error: %s", usage);
        return 1;
    }

    bool reverse = false;
    char* dirpath = argv[1];
    char* syncpipe = argv[2];

    // Read from syncpipe to synchronize with the parent process
    int fd = open(syncpipe, O_RDONLY);
    if (fd < 0) {
        perror(syncpipe);
        return 1;
    }
    char buf;
    if (read(fd, &buf, 1) != 1) {
        perror("read from syncpipe");
        close(fd);
        return 1;
    }

    rephit_dir(dirpath);
    return 0;
}