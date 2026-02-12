#include <argp.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cache_ext_mru.skel.h"
#include "dir_watcher.h"
const char *FILENAME = __FILE__;
typedef struct cache_ext_mru_bpf cache_ext_bpf;
#include "cache_ext_log_util.h"

char *USAGE = "Usage: ./cache_ext_mru --watch_dir <dir> --cgroup_size <size> --cgroup_path <path>\n";

int main(int argc, char **argv)
{
	int ret = 1;
	struct cache_ext_mru_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// Parse command line arguments
	struct cmdline_args args = { 0 };
	if (parse_args(argc, argv, &args))
		return 1;

	// Does watch_dir exist?
	if (access(args.watch_dir, F_OK) == -1) {
		fprintf(stderr, "Directory does not exist: %s\n",
			args.watch_dir);
		return 1;
	}

	// Get full path of watch_dir
	char watch_dir_full_path[PATH_MAX];
	if (realpath(args.watch_dir, watch_dir_full_path) == NULL) {
		perror("realpath");
		return 1;
	}

	// TODO: Enable longer length
	if (strlen(watch_dir_full_path) > 128) {
		fprintf(stderr, "watch_dir path too long\n");
		return 1;
	}

	// Open cgroup directory early
	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		return 1;
	}

	// Open skel
	skel = cache_ext_mru_bpf__open();
	if (skel == NULL) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	// Load programs
	ret = cache_ext_mru_bpf__load(skel);
	if (ret) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	// Initialize watch_dir map
	ret = initialize_watch_dir_map(watch_dir_full_path, bpf_map__fd(skel->maps.inode_watchlist), true);
	if (ret) {
		perror("Failed to initialize watch_dir map");
		goto cleanup;
	}

	// Attach cache_ext_ops to the specific cgroup
	link = bpf_map__attach_cache_ext_ops(skel->maps.mru_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach cache_ext_ops to cgroup");
		goto cleanup;
	}

	// Wait for keyboard input
	printf("Press any key to exit...\n");
	getchar();
	ret = 0;

cleanup:
	print_cache_stats(skel);
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_mru_bpf__destroy(skel);
	return ret;
}
