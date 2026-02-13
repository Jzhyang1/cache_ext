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

const char *usage = "Usage: scan [-r] <directory>\n";

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "%s", usage);
        return 1;
    }

    bool reverse = false;
    char* dirpath = NULL;
    if (argc >= 3 && strcmp(argv[1], "-r") == 0) {
        reverse = true;
        dirpath = argv[2];
    } else {
        dirpath = argv[1];
    }

    scan_dir(dirpath, reverse);
    return 0;
}