#include <stdio.h>
#include <stdint.h>
#include <bpf/bpf.h>

// Input parsing

struct cmdline_args {
	char *watch_dir;
	uint64_t cgroup_size;
	char *cgroup_path;
};

static struct argp_option options[] = {
	{ "watch_dir", 'w', "DIR", 0, "Directory to watch" },
	{"cgroup_size", 's', "SIZE", 0, "Size of the cgroup"},
	{"cgroup_path", 'c', "PATH", 0, "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)"},
	{ 0 },
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	switch (key) {
	case 'w':
		args->watch_dir = arg;
		break;
    case 's':
        errno = 0;
        args->cgroup_size = strtoull(arg, NULL, 10);
        if (errno) args->cgroup_size = 0;
        break;
    case 'c':
        args->cgroup_path = arg;
        break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int parse_args(int argc, char **argv, struct cmdline_args *args) {
	struct argp argp = { options, parse_opt, 0, 0 };
	argp_parse(&argp, argc, argv, 0, 0, args);

	if (args->watch_dir == NULL) {
		fprintf(stderr, "Missing required argument: watch_dir\n");
		return 1;
	}
	if (args->cgroup_size == 0) {
        fprintf(stderr, "Invalid cgroup size: %lu\n", args->cgroup_size);
        return 1;
	}
	if (args->cgroup_path == NULL) {
		fprintf(stderr, "Missing required argument: cgroup_path\n");
		return 1;
	}
	return 0;
}

// Cache statistics printing

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