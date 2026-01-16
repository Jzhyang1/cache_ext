#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define OFFSET_STEP 4096

void scan_file(const char *filepath) {
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

    off_t filesize = st.st_size;
    unsigned char buf;
    for (off_t offset = 0; offset < filesize; offset += OFFSET_STEP) {
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

void scan_dir(const char *dirpath) {
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
            scan_dir(filepath);
            continue;
        }
        if (entry->d_type != DT_REG)
            continue; // Only regular files

        snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);
        scan_file(filepath);
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
        return 1;
    }

    scan_dir(argv[1]);
    return 0;
}