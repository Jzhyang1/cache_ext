#include <stdio.h>
#include <stdint.h>
#include <bpf/bpf.h>

static void print_cache_stats(struct cache_ext_lru_bpf *skel) {
    uint32_t key;
    uint64_t value;

	// we write to a file because printing gets messed up sometimes
	FILE *fp = fopen("cache_stats.txt", "a");

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