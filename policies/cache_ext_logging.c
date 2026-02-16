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
#include "cache_ext_logging.skel.h"
const char *FILENAME = __FILE__;
typedef struct cache_ext_logging_bpf cache_ext_bpf;
#include "cache_ext_log_util.h"


char *USAGE = "Usage: ./cache_ext_logging --watch_dir <dir> --cgroup_path <path>\n";

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
 * Userspace handling for logging requests
 ***********************************************************/

struct userspace_event {
	uint64_t address_space;	// some identifier
	uint64_t index;	// page offset in file
	uint64_t nr_event; // order of access
};

#define OUTPUT_EVENT_BUFFER_SIZE 4096
userspace_event output_buffer[OUTPUT_EVENT_BUFFER_SIZE];
uint64_t output_buffer_head = 0;

static int handle_event(void *ctx, void *data, size_t data_sz) {
	struct userspace_event *event = (struct userspace_event *)data;
	output_buffer[output_buffer_head] = *event;

	// TODO consider putting this into a separate thread if writing to file becomes a bottleneck
	if (++output_buffer_head == OUTPUT_EVENT_BUFFER_SIZE) {
		// Buffer full, write to file
		FILE *f = fopen("page_accesses.log", "a");
		if (f == NULL) {
			perror("Failed to open log file");
			return -1;
		}

		for (uint64_t i = 0; i < output_buffer_head; ++i) {
			fprintf(f, "%llu: Address Space: %llu, Page Index: %llu\n",
				output_buffer[i].nr_event, output_buffer[i].address_space, output_buffer[i].index);
		}
		fclose(f);
		output_buffer_head = 0;
	}
	
	return 0;
}

int main(int argc, char **argv) {
	struct cmdline_args args = { 0 };
	struct cache_ext_logging_bpf *skel = NULL;
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

	skel = cache_ext_logging_bpf__open();
	if (!skel) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	watch_dir_path_len_map(skel) = strlen(watch_dir_path);
	strcpy(watch_dir_path_map(skel), watch_dir_path);

	if (cache_ext_logging_bpf__load(skel)) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	if (initialize_watch_dir_map(watch_dir_path, bpf_map__fd(inode_watchlist_map(skel)), true)) {
		perror("Failed to initialize watch_dir map");
		goto cleanup;
	}

	struct ring_buffer *events = ring_buffer__new(bpf_map__fd(skel->maps.userspace_events), handle_event, NULL, NULL);
	if (!events) {
		perror("Failed to create ring buffer");
		goto cleanup;
	}

	link = bpf_map__attach_cache_ext_ops(skel->maps.log_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach cache_ext_ops to cgroup");
		goto cleanup;
	}

	// This is necessary for the dir_watcher functionality
	if (cache_ext_logging_bpf__attach(skel)) {
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
	cache_ext_logging_bpf__destroy(skel);
	return ret;
}
