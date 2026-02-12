#include <argp.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "dir_watcher.h"
#include "cache_ext_prefetch.skel.h"
const char *FILENAME = __FILE__;
typedef struct cache_ext_prefetch_bpf cache_ext_bpf;
#include "cache_ext_log_util.h"


char *USAGE = "Usage: ./cache_ext_prefetch --watch_dir <dir> --cgroup_path <path>\n";

static volatile sig_atomic_t exiting;

static void sig_handler(int signo) {
	exiting = 1;
}

/*
 * Validate watch_dir
 *
 * watch_dir_full_path must be able to hold PATH_MAX bytes.
 */
static int validate_watch_dir(const char *watch_dir, char *watch_dir_full_path) {
	// Does watch_dir exist?
	if (access(watch_dir, F_OK) == -1) {
		fprintf(stderr, "Directory does not exist: %s\n", watch_dir);
		return 1;
	}

	// Get full path of watch_dir
	if (realpath(watch_dir, watch_dir_full_path) == NULL) {
		perror("realpath");
		return 1;
	}

	// BPF policy restriction
	if (strlen(watch_dir_full_path) > 128) {
		fprintf(stderr, "watch_dir path too long\n");
		return 1;
	}

	return 0;
}

/***********************************************************
 * Userspace handling for prefetch requests
 ***********************************************************/

struct userspace_event {
	uint64_t user_address_space;	// this is the value in inverse_mapping_registry that userspace sends to identify the address_space
	uint64_t index;	// page offset in file
	uint64_t nr_pages;	// number of pages to prefetch
};

static uint64_t nr_events = 0;
static int handle_event(void *ctx, void *data, size_t data_sz) {
	++nr_events;

	struct userspace_event *event = (struct userspace_event *)data;
	// Print prefetch info every 1000 events for debugging
	if (nr_events % 1000 == 0) {
		printf("Prefetch request: address_space=%llu, index=%llu, nr_pages=%llu\n",
			event->user_address_space, event->index, event->nr_pages);
		// Also for debugging, send the next index as a userspace_event request for a prefetch

		int fd = *(int *)ctx;
		struct userspace_event next_event = {
			.user_address_space = event->user_address_space,
			.index = event->index + 1,	// this is just for testing purposes
			.nr_pages = 1,
		};
		struct bpf_test_run_opts opts = {
			.sz = sizeof(opts),
			.ctx_in = &next_event,
			.ctx_size_in = sizeof(next_event),
		};
		int err = bpf_prog_test_run_opts(fd, &opts);
		if (err) {
			perror("Failed to run pf_prefetch_folios program");
			return 0;
		}
	}
	return 0;
}

int main(int argc, char **argv) {
	struct cmdline_args args = { 0 };
	struct cache_ext_prefetch_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	struct sigaction sa;
	char watch_dir_path[PATH_MAX];
	int cgroup_fd = -1;
	int ret = 1;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	if (parse_args(argc, argv, &args))
		return 1;

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = sig_handler;

	// Install signal handler
	if (sigaction(SIGINT, &sa, NULL)) {
		perror("Failed to set up signal handling");
		return 1;
	}

	if (validate_watch_dir(args.watch_dir, watch_dir_path))
		return 1;

	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		return 1;
	}

	skel = cache_ext_prefetch_bpf__open();
	if (!skel) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	watch_dir_path_len_map(skel) = strlen(watch_dir_path);
	strcpy(watch_dir_path_map(skel), watch_dir_path);

	if (cache_ext_prefetch_bpf__load(skel)) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	if (initialize_watch_dir_map(watch_dir_path, bpf_map__fd(inode_watchlist_map(skel)), true)) {
		perror("Failed to initialize watch_dir map");
		goto cleanup;
	}

	// Get fd of reconfigure program
	int prefetch_prog_fd = bpf_program__fd(skel->progs.pf_prefetch_folios);

	struct ring_buffer *events = ring_buffer__new(bpf_map__fd(skel->maps.userspace_events), handle_event, &prefetch_prog_fd, NULL);
	if (!events) {
		perror("Failed to create ring buffer");
		goto cleanup;
	}

	link = bpf_map__attach_cache_ext_ops(skel->maps.pf_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach page_cache_ext_ops to cgroup");
		goto cleanup;
	}

	// This is necessary for the dir_watcher functionality
	if (cache_ext_prefetch_bpf__attach(skel)) {
		perror("Failed to attach BPF skeleton");
		goto cleanup;
	}

	// Wait for keyboard input
	printf("Press any key to exit...\n");
	getchar();
	ret = 0;

cleanup:
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_prefetch_bpf__destroy(skel);
	return ret;
}
