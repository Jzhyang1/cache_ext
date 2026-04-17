#!/bin/python

import argparse
import re
import os
import random

from typing import Any
args : Any = None

try:
    from rapidfuzz.distance import DamerauLevenshtein
except ImportError:
    class DamerauLevenshteinMissing:
        @staticmethod
        def distance(a, b):
            raise NotImplementedError("DamerauLevenshtein distance not available, please install rapidfuzz")
    DamerauLevenshtein = DamerauLevenshteinMissing

try:
    from lru import LRU as LRUImpl
    class EmptyLRUDict:
        def __setitem__(self, key, value):
            pass
        def __contains__(self, key):
            return False
        def __len__(self):
            return 0
    def LRUExists(size):
        if size == 0:
            return EmptyLRUDict()
        return LRUImpl(size)
    LRU = LRUExists
except ImportError:
    def LRUMissing(size):
        if args.ignore_lru:
            return dict()
        raise NotImplementedError("LRU cache not available, please install lru-dict or use --ignore-lru flag")
    LRU = LRUMissing

# Arguments to the program:
# check.py <method> <logfile_ref> <logfile_pred> [--size cache_size] [--lookahead lookahead_size]

# The program uses the page accesses from logfile_ref to model how well the prefetcher can
# perform with knowledge of the future page accesses on a different log logfile_pred.
# Eviction is performed using LRU

# Error handling
error_count = 0
MAX_ERROR_COUNT = 100
def perror(*args):
    global error_count
    error_count += 1
    if error_count < MAX_ERROR_COUNT:
        print(*args)
    elif error_count == MAX_ERROR_COUNT:
        print("MAX_ERROR_COUNT exceeded, stopping logging")

def print_hit_miss(hits, total):
    print(f"Total accesses: {total}")
    print(f"Cache hits: {hits}")
    print(f"Hit rate: {hits / total:.2%}")

def generate_markov_model(logfile_ref, context_size):
    hist = {}    # maps {addr: {next_addr: count}}
    with LogFileRead(logfile_ref) as f:
        prev_addrs = [None] * context_size
        for access in f:
            if access.type != 0:
                continue
            addr = access.page_index
            minihist = hist.setdefault(tuple(prev_addrs), {})
            minihist[addr] = minihist.get(addr, 0) + 1
            prev_addrs = prev_addrs[1:] + [addr]
    # Compile hist into a map {addr: [(PDF, next_addr)]}
    ret = {}
    for addr, entries in hist.items():
        total = 0
        for next_addr, count in entries.items():
            total += count
        accum, miniret = 0, []
        for next_addr, count in entries.items():
            accum += count
            miniret.append((accum/total, next_addr))
        ret[addr] = miniret
    print("model is of size", len(ret))
    return ret

def markov_select_next(model, addr):
    if addr not in model:
        return None
    miniret = model[addr]
    sel = random.random()
    for prob, ret in miniret:
        if sel < prob: return ret
    return ret

def markov_model_log_files(logfile_ref, logfile_pred, cache_size, lookahead_size, context_size):
    assert cache_size == 0 # we disable this for now
    model = generate_markov_model(logfile_ref, context_size)
    hits = 0
    total = 0

    with LogFileRead(logfile_pred) as f:
        prev_addrs = [None] * context_size
        cache = set()
        for access in f:
            if access.type != 0:
                continue
            addr = access.page_index
            if addr in cache:
                hits += 1

            prev_addrs = prev_addrs[1:] + [addr]
            ref_addrs = tuple(prev_addrs)
            cache = set()   # reset
            for _ in range(lookahead_size):
                pred_addr = markov_select_next(model, ref_addrs)
                if pred_addr is not None:
                    cache.add(pred_addr)
                ref_addrs = (*ref_addrs[1:], pred_addr)
            total += 1
    print_hit_miss(hits, total)

# def markov_model_log_files(logfile_ref, logfile_pred, cache_size, lookahead_size, context_size):
#     assert lookahead_size <= cache_size
#     model = generate_markov_model(logfile_ref, context_size)
#     cache = LRU(cache_size)
#     hits = 0
#     total = 0

#     with LogFileRead(logfile_pred) as f:
#         prev_addrs = [None] * context_size
#         for access in f:
#             if access.type != 0:
#                 continue
#             addr = access.page_index
#             if addr in cache:
#                 hits += 1
#             else:
#                 cache[addr] = None
            
#             prev_addrs = prev_addrs[1:] + [addr]
#             ref_addrs = tuple(prev_addrs)
#             for _ in range(lookahead_size):
#                 pred_addr = markov_select_next(model, ref_addrs)
#                 if pred_addr is not None:
#                     cache[pred_addr] = None
#                 ref_addrs = (*ref_addrs[1:], pred_addr)
#             total += 1
#     print_hit_miss(hits, total)

def sched_aware_markov_model_log_files(logfile_ref, logfile_pred, cache_size, lookahead_size, context_size):
    # Get all PIDs and for each, build up a list of page accesses from when the PID was certainly active
    cached_pid_list = f'{logfile_pred}.pids.log'
    if os.path.exists(cached_pid_list):
        with open(cached_pid_list, 'r') as f:
            all_pids = set([int(line.strip()) for line in f.readlines()])
    else:
        active_pids = set()
        pid_activities = {}  # maps to count of page accesses while each pid is active
        with LogFileRead(logfile_pred) as f:
            for access in f:
                if access.type == 1:
                    # page_index is dst pid for type == 1
                    active_pids.discard(access.address_space)
                    active_pids.add(access.page_index)
                elif access.type == 0:
                    for pid in active_pids:
                        pid_activities[pid] = pid_activities.get(pid, 0) + 1
        # We don't want OS activities counted in our simulation
        all_pids = [pid for pid, count in pid_activities.items() if count > 10000]
        with open(cached_pid_list, 'w') as f:
            for pid in all_pids:
                f.write(f'{pid}\n')

    print("Number of possible PIDs:", len(all_pids))
    if len(all_pids) > 20:
        print("Error: too many possible PIDs")
        raise Exception()

    pid_caches = {
        pid:LogFileWrite(f'{logfile_pred}.{pid}.log') for pid in all_pids
    }
    # run through the file again to sort entries into cache files
    if not all(f.exists() for _, f in pid_caches.items()):
        pid_writes = {
            pid:f.__enter__() for pid, f in pid_caches.items()
        }
        active_pids = set()
        with LogFileRead(logfile_pred) as f:
            for access in f:
                if access.type == 1:
                    # page_index is dst pid for type == 1
                    active_pids.discard(access.address_space)
                    active_pids.add(access.page_index)
                elif access.type == 0:
                    for pid in active_pids:
                        if pid in pid_writes:
                            pid_writes[pid](
                                access.nr_event, access.type, access.drop_count, 
                                access.address_space, access.page_index, access.pid_self, access.pid_next
                            )
    for pid, cache_file in pid_caches.items():
        cache_file.__exit__(None, None, None)
        print("[", pid, "]")
        markov_model_log_files(logfile_ref, cache_file.path, cache_size, lookahead_size, context_size)


def readahead_log_files(logfile_ref, logfile_pred, cache_size, lookahead_size, **kwargs):
    assert lookahead_size <= cache_size

    for logfile in [logfile_ref, logfile_pred]:
        cache = LRU(cache_size)
        hits = 0
        total = 0
        with LogFileRead(logfile) as f:
            for access in f:
                addr = access.page_index
                if addr in cache:
                    hits += 1
                else:
                    cache[addr] = None
                
                ref_addr = addr
                for i in range(lookahead_size):
                    ref_addr = addr + i
                    cache[ref_addr] = None
                total += 1
        print(f"Finished processing {logfile}, hits so far: {hits} out of {total} accesses ({hits / total:.2%} hit rate)")
    return hits, total

def matching_log_files(logfile_ref, logfile_pred, cache_size, lookahead_size, context_size, **kwargs):
    actual_cache_size = cache_size - lookahead_size if cache_size > lookahead_size else 0
    max_hits, max_total = 0, 0
    for i in range(context_size):
        cache = LRU(actual_cache_size)
        lookahead = LRU(cache_size - actual_cache_size)
        hits, total = 0, 0

        with LogFileRead(logfile_pred) as f, LogFileRead(logfile_ref) as model:
            # Populate the first lookahead_size entries of the model into the cache
            model_iter = iter(model)
            for _ in range(lookahead_size + i):
                try:
                    ref_addr = next(model_iter).page_index
                    if ref_addr is not None:
                        lookahead[ref_addr] = None
                except StopIteration:
                    pass
            for access in f:
                addr = access.page_index
                if addr in cache or addr in lookahead:
                    hits += 1
                else:
                    cache[addr] = None

                # Prefetch
                try:
                    ref_addr = next(model_iter).page_index
                    if ref_addr is not None:
                        lookahead[ref_addr] = None
                except StopIteration:
                    pass
                total += 1
        if hits > max_hits:
            max_hits, max_total = hits, total
    print_hit_miss(max_hits, max_total)

def sanity_check(logfile_ref, logfile_pred, **kwargs):
    # Counts the missing access log entries in logfile_pred and logfile_ref
    for logfile in [logfile_ref, logfile_pred]:
        if logfile is None: continue

        # Check that PIDs are consistent between sched logs and page access logs
        sched_events, page_access_events = 0, 0
        active_pids = set() # PIDs in runqueue based on sched logs
        pid_nexts = []      # Assume that the runqueue doesn't change 
        pid_matched_to = 0  #  then we can go through the pid_nexts and match to each sched interrupt
        pid_access_not_active = 0 # Count accesses where the pid_self is not in active_pids, which shouldn't happen
        with LogFileRead(logfile) as f:
            start_n, cur_n, count = None, 0, 0
            source_says = 0
            for access in f:
                if access.type == 1:
                    # page_index is dst_pid for type == 1
                    active_pids.discard(access.address_space)
                    active_pids.add(access.page_index)
                    if pid_matched_to < len(pid_nexts) and access.page_index == pid_nexts[pid_matched_to]:
                        # our scheduler log is consistent with the scheduler state logged during page accesses
                        pid_matched_to += 1
                    sched_events += 1
                elif access.type == 0:
                    if (len(pid_nexts) == 0 or access.pid_next != pid_nexts[-1])\
                          and access.pid_next > 100: # any pid_next <= 100 is likely an OS activity
                        pid_nexts.append(access.pid_next)
                    if access.pid_self not in active_pids:
                        pid_access_not_active += 1
                    page_access_events += 1

                got_n = access.nr_event
                source_says = access.drop_count
                if start_n is None:
                    start_n = got_n
                count += 1
                cur_n = got_n
        if start_n is None: start_n = 0
        range_n = cur_n - start_n + 1
        missing = range_n - count
        print(f"Page access events: {page_access_events}, scheduler events: {sched_events}")
        print(f"Missing entries in {logfile} log: {missing} of {range_n} ({missing / range_n if range_n > 0 else 0:.2%})")
        print(f"Source says missing {source_says} of {cur_n} ({source_says / cur_n if cur_n > 0 else 0:.2%})")
        print(f"Scheduler consistent with {pid_matched_to/len(pid_nexts) if pid_nexts else 0:.2%} of page accesses")
        print(f"Accesses with non-active PIDs: {pid_access_not_active} of {page_access_events} ({pid_access_not_active / page_access_events if page_access_events > 0 else 0:.2%})")

def compare_log_files(logfile_ref, logfile_pred, **kwargs):
    # Ignore cache_size and lookahead_size
    # Just compare the addresses accessed via levenshtein distance
    seq1 = []
    seq2 = []
    with LogFileRead(logfile_ref) as f1, LogFileRead(logfile_pred) as f2:
        seq1 = [access.page_index for access in f1]
        seq2 = [access.page_index for access in f2]
    distance = DamerauLevenshtein.distance(seq1, seq2)
    longer_length = max(len(seq1), len(seq2))
    print_hit_miss(longer_length - distance, longer_length)

methods = {
    'compare': compare_log_files,
    'readahead': readahead_log_files,
    'model': markov_model_log_files,
    'smodel': sched_aware_markov_model_log_files,
    'matching': matching_log_files,
    'sanity': sanity_check
}


class LogEntry:
    # every log entry is a 40-byte struct
    # 0-8: nr_event
    # 8-12: type (always 0)
    # 12-16: drop_count
    # 16-24: address_space
    # 24-32: page_index
    # 32-36: pid_self
    # 36-40: pid_next
    def __init__(self, nr_event, type, drop_count, address_space, page_index, pid_self, pid_next):
        self.nr_event = nr_event
        self.type = type
        self.drop_count = drop_count
        self.address_space = address_space
        self.page_index = page_index
        self.pid_self = pid_self
        self.pid_next = pid_next
class LogFileIterator:
    def __init__(self, file):
        self.file = file
    
    def __iter__(self):
        return self
    
    def __next__(self):
        data = self.file.read(40)
        if not data:
            raise StopIteration
        nr_event = int.from_bytes(data[0:8], 'little')
        type = int.from_bytes(data[8:12], 'little')
        drop_count = int.from_bytes(data[12:16], 'little')
        address_space = int.from_bytes(data[16:24], 'little')
        page_index = int.from_bytes(data[24:32], 'little')
        pid_self = int.from_bytes(data[32:36], 'little')
        pid_next = int.from_bytes(data[36:40], 'little')
        return LogEntry(nr_event, type, drop_count, address_space, page_index, pid_self, pid_next)

class LogFileRead:
    def __init__(self, path):
        self.path = path
        self.file = None
    def __enter__(self):
        self.file = open(self.path, 'rb')
        # return an iterable over the log entries
        return LogFileIterator(self.file)
    def __exit__(self, exc_type, exc_value, traceback):
        if self.file is not None:
            self.file.close()

class LogFileWrite:
    def __init__(self, path):
        self.path = path
        self.file = None
    def exists(self):
        return os.path.exists(self.path)
    def __enter__(self):
        self.file = f = open(self.path, 'wb')
        def write_entry(nr_event, type, drop_count, address_space, page_index, pid_self, pid_next):
            f.write(nr_event.to_bytes(8, 'little') +
                    type.to_bytes(4, 'little') +
                    drop_count.to_bytes(4, 'little') +
                    address_space.to_bytes(8, 'little') +
                    page_index.to_bytes(8, 'little') +
                    pid_self.to_bytes(4, 'little') +
                    pid_next.to_bytes(4, 'little'))
        return write_entry 
    
    def __exit__(self, exc_type, exc_value, traceback):
        if self.file is not None:
            self.file.close()

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Process a log of scheduler and page activity and compute metrics.')
    argparser.add_argument('method', type=str, help='The method to run, can be one of the following: ' + ','.join(methods.keys()))
    argparser.add_argument('logfile_ref', type=str, help='Path to the reference log file')
    argparser.add_argument('logfile_pred', type=str, default=None, help='Path to the predicted log file')
    argparser.add_argument('--size', '-s', type=int, default=1, help='Cache size in number of pages')
    argparser.add_argument('--lookahead', '-l', type=int, default=0, help='Lookahead size in number of pages')
    argparser.add_argument('--context-size', '-c', type=int, default=1, help='Context size for the Markov model (only used for the "model" method)')
    argparser.add_argument('--ignore-lru', action='store_true', help='If LRU is not available, use a set for the cache (for testing purposes)')

    args = argparser.parse_args()

    methods[args.method](
        args.logfile_ref, 
        args.logfile_pred,
        cache_size = args.size,
        lookahead_size = args.lookahead,
        context_size = args.context_size
    )