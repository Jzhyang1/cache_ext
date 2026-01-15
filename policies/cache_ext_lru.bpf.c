#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

static u64 hits = 0;
static u64 misses = 0;

// Map to access stats in user space
#define HITS_INDEX 0
#define MISSES_INDEX 1
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u64);
} lru_stats SEC(".bss");

s32 BPF_STRUCT_OPS_SLEEPABLE(lru_init, struct mem_cgroup *memcg) {
	hits = 0;
	misses = 0;
	return 0;
}

void BPF_STRUCT_OPS(lru_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg) {
	// only sync the local variables with map on eviction
	u32 hits_index = HITS_INDEX;
	u32 misses_index = MISSES_INDEX;
	bpf_map_update_elem(&lru_stats, &hits_index, &hits, BPF_ANY);
	bpf_map_update_elem(&lru_stats, &misses_index, &misses, BPF_ANY);
}

void BPF_STRUCT_OPS(lru_folio_accessed, struct folio *folio) {
	__sync_fetch_and_add(&hits, 1);
}

void BPF_STRUCT_OPS(lru_folio_evicted, struct folio *folio) {
	return;
}

void BPF_STRUCT_OPS(lru_folio_added, struct folio *folio) {
	__sync_fetch_and_add(&misses, 1);
}

SEC(".struct_ops.link")
struct cache_ext_ops lru_ops = {
	.init = (void *)lru_init,
	.evict_folios = (void *)lru_evict_folios,
	.folio_accessed = (void *)lru_folio_accessed,
	.folio_evicted = (void *)lru_folio_evicted,
	.folio_added = (void *)lru_folio_added,
};
