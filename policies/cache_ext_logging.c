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
// double buffering for userspace events - we write to file in batches to reduce overhead, but we don't want to miss events while writing
struct userspace_event output_buffer[OUTPUT_EVENT_BUFFER_SIZE][2];
int active_buffer = 0;
uint64_t output_buffer_head = 0;

static char log_filename[256];

static int flush_events(struct userspace_event *buffer, size_t count) {
	FILE *f = fopen(log_filename, "a");
	if (f == NULL) {
		perror("Failed to open log file");
		return -1;
	}

	for (size_t i = 0; i < count; ++i) {
		fprintf(f, "%llu: Address Space: %llu, Page Index: %llu\n",
			buffer[i].nr_event, buffer[i].address_space, buffer[i].index);
	}
	fclose(f);
	return 0;
}

static int create_file() {
	// first check if file exists, if it exists choose a different name
	for (int i = 0; ; ++i) {
		snprintf(log_filename, sizeof(log_filename), "page_accesses_%d.log", i);
		if (access(log_filename, F_OK) == -1) {
			break;
		}
	}
	return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
	struct userspace_event *event = (struct userspace_event *)data;
	output_buffer[active_buffer][output_buffer_head] = *event;

	uint64_t next_index = (output_buffer_head + 1) % OUTPUT_EVENT_BUFFER_SIZE;
	output_buffer_head = next_index;

	// TODO consider putting this into a separate thread if writing to file becomes a bottleneck
	if (next_index == 0) {
		// Buffer full, write to file
		struct userspace_event *prev_buf = output_buffer[active_buffer];
		active_buffer = 1 - active_buffer; // switch buffer

		flush_events(prev_buf, OUTPUT_EVENT_BUFFER_SIZE);
	}
	
	return 0;
}

int main(int argc, char **argv) {
	struct cmdline_args args = { 0 };
	struct cache_ext_logging_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	struct sigaction sa;
	struct ring_buffer *events = NULL;
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

	events = ring_buffer__new(bpf_map__fd(skel->maps.userspace_events), handle_event, NULL, NULL);
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

	// Create log file
	if (create_file() != 0) {
		fprintf(stderr, "Failed to create log file\n");
		goto cleanup;
	}

	// Poll until exit signal is received
	while (!exiting) {
		ret = ring_buffer__poll(events, -1); // infinite timeout
		
		if (ret == -EINTR) {
			ret = 0;
			break;
		} else if (ret < 0) {
			fprintf(stderr, "error polling ring buffer: %d\n", ret);
			ret = 1;
			goto cleanup;
		} else {
			ret = 0;
		}
	}

cleanup:
	flush_events(output_buffer[active_buffer], output_buffer_head);
	if (events != NULL) ring_buffer__free(events);
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_logging_bpf__destroy(skel);
	return ret;
}
