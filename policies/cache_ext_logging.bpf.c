#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";


/***********************************************************
 * This part handles sending page accesses to be stored to a file via userspace
 * We go from eBPF (folio_accessed) -> userspace (listens to ring buffer) 
 * 	-> write to file
 ***********************************************************/

#define EVENT_PAGE_ACCESS 0
#define EVENT_SCHED_SWITCH 1

struct userspace_event {
	u32 nr_event; // order of access
	u32 type; 	// 0 for access, 1 for sched switch
	u64 timestamp;
	union {
		struct {
			u64 address_space;
			u64 index;	// page offset in file
		};
		struct {
			u64 prev_pid;
			u64 next_pid;
		};
	};
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 65536);
} userspace_events SEC(".maps");	// this is used to send folio access events to userspace

/***********************************************************
 * Actual eBPF program for eviction and prefetching
 ***********************************************************/

static u64 main_list;
static u64 access_count;

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(log_init, struct mem_cgroup *memcg)
{
	main_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (main_list == 0) {
		bpf_printk("cache_ext: init: Failed to create main_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created main_list: %llu\n", main_list);

	return 0;
}

static int bpf_pf_evict_cb(int idx, struct cache_ext_list_node *a)
{
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(log_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	if (bpf_cache_ext_list_iterate(memcg, main_list, bpf_pf_evict_cb, eviction_ctx) < 0) {
		bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
		return;
	}
}


void BPF_STRUCT_OPS(log_folio_accessed, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	struct userspace_event event = {
		.address_space = (u64)folio->mapping,
		.index = folio->index,
		.nr_event = access_count++,
		.timestamp = bpf_ktime_get_ns(),
		.type = EVENT_PAGE_ACCESS,
	};
	bpf_ringbuf_output(&userspace_events, &event, sizeof(event), 0);
}

void BPF_STRUCT_OPS(log_folio_evicted, struct folio *folio) {
	// if (bpf_cache_ext_list_del(folio)) {
	// 	bpf_printk("cache_ext: Failed to delete folio from list\n");
	// 	return;
	// }
}

void BPF_STRUCT_OPS(log_folio_added, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	if (bpf_cache_ext_list_add_tail(main_list, folio)) {
		bpf_printk("cache_ext: added: Failed to add folio to main_list\n");
		return;
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops log_ops = {
	.init = (void *)log_init,
	.evict_folios = (void *)log_evict_folios,
	.folio_evicted = (void *)log_folio_evicted,
	.folio_added = (void *)log_folio_added,
	.folio_accessed = (void *)log_folio_accessed,
};

/***********************************************************
 * BPF program to log scheduling events
 ***********************************************************/

// Hook into the sched_switch tracepoint
SEC("tracepoint/sched/sched_switch")
int bpf_prog_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    // Read the PID of the next task being scheduled
    pid_t next_pid = ctx->next_pid;
    pid_t prev_pid = ctx->prev_pid;
    
    // Create an event to send to userspace
	struct userspace_event event = {
		.prev_pid = prev_pid,
		.next_pid = next_pid,
		.nr_event = access_count++,
		.timestamp = bpf_ktime_get_ns(),
		.type = EVENT_SCHED_SWITCH,
	};
	
	// Send the event to userspace via the ring buffer
	bpf_ringbuf_output(&userspace_events, &event, sizeof(event), 0);
    
    return 0;
}