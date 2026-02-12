#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

/***********************************************************
 * This part handles sending prefetch hints to be actually executed
 * We go from eBPF (folio_accessed) -> userspace (listens to ring buffer) 
 * 	-> eBPF (prefetch_folios) -> kernel (prefetch)
 ***********************************************************/
#ifndef __kptr
#define __kptr __attribute__((btf_type_tag("kptr")))
#endif
#ifndef __kptr_ref
#define __kptr_ref __attribute__((btf_type_tag("kptr_ref")))
#endif

struct address_space_wrapper {
	struct address_space __kptr __kptr_ref *mapping;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);	// TODO: configurable amount of address_spaces that can be buffered for prefetching
	__type(key, u64);
	__type(value, struct address_space_wrapper);
} inverse_mapping_registry SEC(".maps");	// this translates address_space pointers from userspace descriptors

struct userspace_event {
	u64 user_address_space;	// this is the value in inverse_mapping_registry that userspace sends to identify the address_space
	u64 index;	// page offset in file
	u64 nr_pages;	// number of pages to prefetch
};

static inline struct address_space_wrapper* get_address_space_from_userspace_key(u64 key) {
	return bpf_map_lookup_elem(&inverse_mapping_registry, &key);
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} userspace_events SEC(".maps");	// this is used to send folio access events to userspace, who then handles prefetching

/***********************************************************
 * This part is just metadata and eviction policy
 ***********************************************************/

 struct folio_metadata {
	u64 userspace_key;
 };

 struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct folio_metadata);
	__uint(max_entries, 4000000);
} folio_metadata_map SEC(".maps");

/***********************************************************
 * Syscall wrapper to perform prefetch requests from userspace
 ***********************************************************/

SEC("syscall")
void pf_prefetch_folios(void* ctx) {
	bpf_printk("cache_ext: prefetch_folios called\n");
	struct userspace_event *event = (struct userspace_event *)ctx;
	struct address_space_wrapper *wrapper = get_address_space_from_userspace_key(event->user_address_space);
	if (!wrapper) {
		bpf_printk("cache_ext: prefetch: Failed to get address_space from userspace key\n");
		return;
	}
	struct address_space *mapping = wrapper->mapping;
	// prefetch via kernel function
	bpf_cache_ext_prefetch(mapping, event->index, event->nr_pages);
}

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

s32 BPF_STRUCT_OPS_SLEEPABLE(pf_init, struct mem_cgroup *memcg)
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

void BPF_STRUCT_OPS(pf_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	if (bpf_cache_ext_list_iterate(memcg, main_list, bpf_pf_evict_cb, eviction_ctx) < 0) {
		bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
		return;
	}
}


void BPF_STRUCT_OPS(pf_folio_accessed, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	u64 address_space_key = (u64)folio->mapping;
	struct address_space_wrapper *wrapper = get_address_space_from_userspace_key(address_space_key);
	if (!wrapper) {
		// add it and and possibly evict an old one
		struct address_space_wrapper wrapper = {
			.mapping = bpf_mapping_acquire(folio->mapping),
		};
		if (bpf_map_update_elem(&inverse_mapping_registry, &address_space_key, &wrapper, BPF_ANY)) {
			bpf_printk("cache_ext: access: Failed to update inverse mapping registry\n");
			return;
		}
	}

	struct userspace_event event = {
		.user_address_space = address_space_key,
		.index = folio->index,
		.nr_pages = 1,	// for now we just assume that all folios are 1 page, but this can be extended in the future
	};
	bpf_ringbuf_output(&userspace_events, &event, sizeof(event), 0);
}

void BPF_STRUCT_OPS(pf_folio_evicted, struct folio *folio) {
	// if (bpf_cache_ext_list_del(folio)) {
	// 	bpf_printk("cache_ext: Failed to delete folio from list\n");
	// 	return;
	// }
}

void BPF_STRUCT_OPS(pf_folio_added, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	if (bpf_cache_ext_list_add_tail(main_list, folio)) {
		bpf_printk("cache_ext: added: Failed to add folio to main_list\n");
		return;
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops pf_ops = {
	.init = (void *)pf_init,
	.evict_folios = (void *)pf_evict_folios,
	.folio_evicted = (void *)pf_folio_evicted,
	.folio_added = (void *)pf_folio_added,
	.folio_accessed = (void *)pf_folio_accessed,
	.prefetch_folios = (void *)pf_prefetch_folios,
};
