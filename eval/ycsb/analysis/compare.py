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
    from lru import LRU
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


def generate_markov_model(logfile_ref, context_size):
    hist = {}    # maps {addr: {next_addr: count}}
    with LogFile(logfile_ref) as f:
        prev_addrs = [None] * context_size
        for access in f:
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
    assert lookahead_size <= cache_size
    model = generate_markov_model(logfile_ref, context_size)
    cache = LRU(cache_size)
    hits = 0
    total = 0

    with LogFile(logfile_pred) as f:
        prev_addrs = [None] * context_size
        for access in f:
            addr = access.page_index
            if addr in cache:
                hits += 1
            else:
                cache[addr] = None
            
            prev_addrs = prev_addrs[1:] + [addr]
            ref_addrs = tuple(prev_addrs)
            for _ in range(lookahead_size):
                pred_addr = markov_select_next(model, ref_addrs)
                if pred_addr is not None:
                    cache[pred_addr] = None
                ref_addrs = (*ref_addrs[1:], pred_addr)
            total += 1
    return hits, total

def readahead_log_files(logfile_ref, logfile_pred, cache_size, lookahead_size, **kwargs):
    assert lookahead_size <= cache_size

    for logfile in [logfile_ref, logfile_pred]:
        cache = LRU(cache_size)
        hits = 0
        total = 0
        with LogFile(logfile) as f:
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

def matching_log_files(logfile_ref, logfile_pred, cache_size, lookahead_size, **kwargs):
    assert lookahead_size <= cache_size
    cache = LRU(cache_size - lookahead_size)
    lookahead = LRU(lookahead_size)
    hits = 0
    total = 0

    with LogFile(logfile_pred) as f, LogFile(logfile_ref) as model:
        # Populate the first lookahead_size entries of the model into the cache
        raise NotImplementedError("matching_log_files method is not implemented yet")
        for _ in range(lookahead_size):
            ref_addr = extract_page_access(model)
            if ref_addr is not None:
                lookahead[ref_addr] = None
        while (addr := extract_page_access(f)) != None:
            if addr in cache or addr in lookahead:
                hits += 1
            else:
                cache[addr] = None

            # Prefetch
            ref_addr = extract_page_access(model)
            if ref_addr is not None:
                lookahead[ref_addr] = None
            total += 1
    return hits, total

def sanity_check(logfile_ref, logfile_pred, **kwargs):
    # Counts the missing access log entries in logfile_pred and logfile_ref
    for logfile in [logfile_ref, logfile_pred]:
        with LogFile(logfile) as f:
            start_n, cur_n, missing = None, 0, 0
            source_says = 0
            for access in f:
                got_n = access.nr_event
                source_says = access.drop_count
                if start_n is None:
                    start_n = got_n
                else:
                    missing += got_n - cur_n - 1
                cur_n = got_n
        if start_n is None: start_n = 0
        print(f"Missing entries in {logfile} log: {missing} of {cur_n - start_n + 1} ({missing / (cur_n - start_n + 1):.2%})")
        print(f"Source says missing {source_says} of {cur_n} ({source_says / cur_n:.2%})")
    return 0, 1

def compare_log_files(logfile_ref, logfile_pred, **kwargs):
    # Ignore cache_size and lookahead_size
    # Just compare the addresses accessed via levenshtein distance
    seq1 = []
    seq2 = []
    with LogFile(logfile_ref) as f1, LogFile(logfile_pred) as f2:
        seq1 = [access.page_index for access in f1]
        seq2 = [access.page_index for access in f2]
    distance = DamerauLevenshtein.distance(seq1, seq2)
    longer_length = max(len(seq1), len(seq2))
    return longer_length - distance, longer_length

methods = {
    'compare': compare_log_files,
    'readahead': readahead_log_files,
    'model': markov_model_log_files,
    'matching': matching_log_files,
    'sanity': sanity_check
}


class LogEntry:
    # every log entry is a 32-byte struct
    # 0-8: nr_event
    # 8-12: type (always 0)
    # 12-16: drop_count
    # 16-24: address_space
    # 24-32: page_index
    def __init__(self, nr_event, type, drop_count, address_space, page_index):
        self.nr_event = nr_event
        self.type = type
        self.drop_count = drop_count
        self.address_space = address_space
        self.page_index = page_index

class LogFileIterator:
    def __init__(self, file):
        self.file = file
    
    def __iter__(self):
        return self
    
    def __next__(self):
        data = self.file.read(32)
        if not data:
            raise StopIteration
        nr_event = int.from_bytes(data[0:8], 'little')
        type = int.from_bytes(data[8:12], 'little')
        drop_count = int.from_bytes(data[12:16], 'little')
        address_space = int.from_bytes(data[16:24], 'little')
        page_index = int.from_bytes(data[24:32], 'little')
        return LogEntry(nr_event, type, drop_count, address_space, page_index)

class LogFile:
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

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Process a log of scheduler and page activity and compute metrics.')
    argparser.add_argument('method', type=str, help='The method to run, can be one of the following: ' + ','.join(methods.keys()))
    argparser.add_argument('logfile_ref', type=str, help='Path to the reference log file')
    argparser.add_argument('logfile_pred', type=str, help='Path to the predicted log file')
    argparser.add_argument('--size', '-s', type=int, default=1, help='Cache size in number of pages')
    argparser.add_argument('--lookahead', '-l', type=int, default=0, help='Lookahead size in number of pages')
    argparser.add_argument('--context-size', '-c', type=int, default=0, help='Context size for the Markov model (only used for the "model" method)')
    argparser.add_argument('--ignore-lru', action='store_true', help='If LRU is not available, use a set for the cache (for testing purposes)')

    args = argparser.parse_args()

    hits, total = methods[args.method](
        args.logfile_ref, 
        args.logfile_pred,
        cache_size = args.size,
        lookahead_size = args.lookahead,
        context_size = args.context_size
    )

    print(f"Total accesses: {total}")
    print(f"Cache hits: {hits}")
    print(f"Hit rate: {hits / total:.2%}")