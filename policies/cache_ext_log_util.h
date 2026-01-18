#include <stdio.h>
#include <stdint.h>
#include <bpf/bpf.h>

static void print_cache_stats(cache_ext_bpf *skel) {
    int fd = bpf_program__fd(skel->progs.save_cache_stats);
    if (fd < 0) {
        perror("Failed to get fd of save_cache_stats program");
        return;
    }
    int err = bpf_prog_test_run_opts(fd, NULL);
    if (err) {
        perror("Failed to run save_cache_stats program");
        return;
    }

    uint32_t key;
    uint64_t value;

	// we write to a file because printing gets messed up sometimes
	FILE *fp = fopen("cache_stats.txt", "a");

    fprintf(fp, "\nCache Statistics %s:\n", FILENAME);
    key = 0; // accesses
    if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.cache_stats), &key, &value) == 0)
        fprintf(fp, "Accesses: %lu\n", value);

    key = 1; // misses
    if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.cache_stats), &key, &value) == 0)
        fprintf(fp, "Misses: %lu\n", value);

    key = 2; // evicts
    if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.cache_stats), &key, &value) == 0)
        fprintf(fp, "Evicts: %lu\n", value);

    fclose(fp);
}