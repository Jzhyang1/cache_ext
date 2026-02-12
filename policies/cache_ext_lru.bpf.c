#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(lru_init, struct mem_cgroup *memcg) {
	reset_counters();
	return 0;
}

void BPF_STRUCT_OPS(lru_evict_folios, struct page_cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg) {
	return;
}

void BPF_STRUCT_OPS(lru_folio_accessed, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	increment_access_counter();
	// bpf_printk("lru_folio_accessed called on %x -> %d\n", folio, access_counter);
}

void BPF_STRUCT_OPS(lru_folio_evicted, struct folio *folio) {
	increment_evict_counter();
}

void BPF_STRUCT_OPS(lru_folio_added, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;
		
	increment_miss_counter();
	u64 miss = miss_counter, access = access_counter;
	if (miss > access) {
		bpf_printk("Miss counter (%d) exceeded access counter (%d) on folio %x\n",
			miss, access, folio);
	}
	// bpf_printk("lru_folio_added called on %x -> %d\n", folio, miss_counter);
}

SEC(".struct_ops.link")
struct page_cache_ext_ops lru_ops = {
	.init = (void *)lru_init,
	.evict_folios = (void *)lru_evict_folios,
	.folio_accessed = (void *)lru_folio_accessed,
	.folio_evicted = (void *)lru_folio_evicted,
	.folio_added = (void *)lru_folio_added,
};
