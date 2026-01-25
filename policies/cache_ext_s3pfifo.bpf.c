#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

#define ENOENT		2  /* include/uapi/asm-generic/errno-base.h */
#define INT64_MAX	(9223372036854775807LL)

/*
* In S3FIFO, we have 3 FIFO lists: small, main, and ghost.
* In S3pFIFO, we have 2 FIFO lists: small and main, 
*  the ghost list is a simple direct-mapped hash.
* A change in behavior: 
*  folios are hashed according to (address_space, offset/folio_size/ASSOC_GROUP) to draw on spatial locality.
*  any miss will be added to the ghost list as 0 (or 1 if folio_accessed is not called after folio_added)
*  any hit will add 1 to the folio ghost entry (inactive -> active)
*  any miss to an "active" ghost entry will add it to the main list
*  any miss to an "inactive" ghost entry will add it to the small list
*  an eviction will set the ghost entry to 0
*
* Expected tradeoffs compared to S3FIFO:
* - more false positives in ghost list, leading to more unused entries in main list
* - faster promotion for actual hot pages due to spatial locality
*
* This should reduce overhead of folio metadata at the cost of some accuracy.
* We wish to see how much accuracy is lost.
*/

#define ASSOC_GROUP 2  	// Number of pages referenced by each ghost entry
						// should equal the number of states of a ghost entry
						// should be a power of 2

#define GHOST_STATE_INACTIVE 1
#define GHOST_STATE_ACTIVE 2
#define MAX_GHOST_VALUE 0x10000

// Set from userspace. In terms of number of pages.
const volatile size_t cache_size = 0;

struct ghost_entry {
	u64 address_space;
	u64 offset;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ghost_entry);
	__type(value, u8);	// active/inactive state
	__uint(map_flags, BPF_F_NO_COMMON_LRU);  // Per-CPU LRU eviction logic
} ghost_map SEC(".maps");


static u64 main_list;
static u64 small_list;

/*
 * This is an approximate value based on what we choose to evict, not what is
 * actually evicted.
 */
static s64 small_list_size = 0;
static s64 main_list_size = 0;

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

/*
 * Hash function for ghost map based on (address_space, offset/folio_size/ASSOC_GROUP)
 */
static inline struct ghost_entry hash_ghost_key(struct folio *folio) {
	struct ghost_entry key = {
		.address_space = (u64)folio->mapping,
		.offset = folio->index & (-ASSOC_GROUP),
	};

	// We can hardly call this a hash, but eBPF has restrictions
	return key;
}

/*
 * Gets an entry from the ghost list
 * returns 255 if not found (to keep in cache if get fails)
 */
static inline u8 get_folio_ghost(struct folio *folio) {
	struct ghost_entry hash = hash_ghost_key(folio);
	u8 *state = bpf_map_lookup_elem(&ghost_map, &hash);
	if (state == NULL) {
		return 255;
	}
	return *state;
}
// returns 255 if not found (to keep in cache if get fails)
static inline u8 get_folio_ghost_decr(struct folio *folio) {
	struct ghost_entry hash = hash_ghost_key(folio);
	u8 *state = bpf_map_lookup_elem(&ghost_map, &hash);
	if (state == NULL) {
		return 255;
	}
	u8 prev_state = *state;
	if (prev_state > 0) {
		*state = prev_state - 1;
	}
	return prev_state;
}
// returns 0 if not found (to add to small cache if not found)
static inline u8 get_folio_ghost_incr(struct folio *folio) {
	struct ghost_entry hash = hash_ghost_key(folio);
	u8 *state = bpf_map_lookup_elem(&ghost_map, &hash);
	if (state == NULL) {
		return 0;
	}
	u8 prev_state = *state;
	if (prev_state < GHOST_STATE_ACTIVE) {
		*state = prev_state + 1;
		return prev_state + 1;
	}
	return prev_state;
}
static inline void zero_folio_ghost(struct folio *folio) {
	struct ghost_entry hash = hash_ghost_key(folio);
	u8 zero = 0;
	bpf_map_update_elem(&ghost_map, &hash, &zero, BPF_ANY);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(s3pfifo_init, struct mem_cgroup *memcg)
{
	reset_counters();
	create_list(main_list, memcg);
	create_list(small_list, memcg);
	return 0;
}

static s64 bpf_s3pfifo_score_main_fn(struct cache_ext_list_node *a) {
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return INT64_MAX;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return INT64_MAX;

	return (s64)get_folio_ghost_decr(a->folio);
}

static int bpf_s3pfifo_score_small_fn(int idx, struct cache_ext_list_node *a)
{
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	u8 ghost_state = get_folio_ghost(a->folio);
	if (ghost_state <= GHOST_STATE_INACTIVE) {
		// Evict
		return CACHE_EXT_EVICT_NODE;
	}

	// Move to main list if freq > GHOST_STATE_INACTIVE
	return CACHE_EXT_CONTINUE_ITER;
}

static void evict_main(struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg)
{
	/*
	 * Iterate from head. If freq > 0, move to tail, freq--.
	 * Otherwise, evict. (When evicting, move to tail in the meantime).
	 */

	struct sampling_options opts = {
		.sample_size = 10,
	};

	if (bpf_cache_ext_list_sample(memcg, main_list, bpf_s3pfifo_score_main_fn, &opts,
				      eviction_ctx)) {
		bpf_printk("cache_ext: evict: Failed to sample main_list\n");
		return;
	}

	if (__sync_sub_and_fetch(&main_list_size, eviction_ctx->nr_folios_to_evict) < 0)
		main_list_size = 0;
}

static void evict_small(struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg)
{
	/*
	 * Iterate from head. If freq > 1, move to main list, otherwise evict.
	 * (When evicting, move to tail in the meantime).
	 *
	 * Use the iterate interface.
	 */

	struct cache_ext_iterate_opts opts = {
		.continue_list = main_list,
		.continue_mode = CACHE_EXT_ITERATE_TAIL,
		.evict_list = CACHE_EXT_ITERATE_SELF,
		.evict_mode = CACHE_EXT_ITERATE_TAIL,
	};

	if (bpf_cache_ext_list_iterate_extended(memcg, small_list, bpf_s3pfifo_score_small_fn, &opts,
						eviction_ctx) < 0) {
		bpf_printk("cache_ext: evict: Failed to iterate small_list\n");
		return;
	}

	if (__sync_fetch_and_sub(&small_list_size, opts.nr_folios_continue) < 0)
		small_list_size = 0;

	if (__sync_fetch_and_add(&main_list_size, opts.nr_folios_continue) < 0)
		main_list_size = opts.nr_folios_continue;
}

void BPF_STRUCT_OPS(s3pfifo_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	// search small list first.
	// when small list has folios to move to main list,
	// add those to main list and then evict from main list if needed.
	evict_small(eviction_ctx, memcg);
	if (main_list_size > 12 * small_list_size) {
		evict_main(eviction_ctx, memcg);
	}
}

void BPF_STRUCT_OPS(s3pfifo_folio_accessed, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;
	increment_access_counter();
	get_folio_ghost_incr(folio);
}

void BPF_STRUCT_OPS(s3pfifo_folio_evicted, struct folio *folio) {
	increment_evict_counter();
	zero_folio_ghost(folio);
}

/*
 * If folio is in the ghost map, add to tail of main list, otherwise add to tail
 * of small list.
 */
void BPF_STRUCT_OPS(s3pfifo_folio_added, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;
	increment_miss_counter();

	u8 count = get_folio_ghost_incr(folio);
	u64 list_to_add;
	if (count >= GHOST_STATE_ACTIVE) {
		// Add to main list
		list_to_add = main_list;
		__sync_fetch_and_add(&main_list_size, 1);
	} else {
		// Add to small list
		list_to_add = small_list;
		__sync_fetch_and_add(&small_list_size, 1);
	}

	if (bpf_cache_ext_list_add_tail(list_to_add, folio)) {
		// TODO: add back to ghost_map?
		bpf_printk("cache_ext: added: Failed to add folio to main_list\n");
		return;
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops s3pfifo_ops = {
	.init = (void *)s3pfifo_init,
	.evict_folios = (void *)s3pfifo_evict_folios,
	.folio_accessed = (void *)s3pfifo_folio_accessed,
	.folio_evicted = (void *)s3pfifo_folio_evicted,
	.folio_added = (void *)s3pfifo_folio_added,
};
