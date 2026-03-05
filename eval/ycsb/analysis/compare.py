#!/bin/python

import argparse
import re
import os
import random

lru_imported = True
try:
    from lru import LRU
except ImportError:
    lru_imported = False
    LRU = lambda x:dict()

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


pattern = re.compile(r'(\d+): Page Access - Address Space: (\d+), Page Index: (\d+), Timestamp: (\d+)')
def extract_page_access(file):
    while True:
        line = file.readline()
        if not line:
            return None
        match = pattern.match(line)
        if match:
            # return (int(match.group(2)), int(match.group(3)))
            return int(match.group(3))

def generate_markov_model(logfile_ref):
    hist = {}    # maps {addr: {next_addr: count}}
    with open(logfile_ref, 'r') as f:
        prev_addr = None
        while (addr := extract_page_access(f)) != None:
            minihist = hist.setdefault(prev_addr, {})
            minihist[addr] = minihist.get(addr, 0) + 1
            prev_addr = addr
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

def markov_model_log_files(logfile_ref, logfile_pred, cache_size, lookahead_size):
    assert lookahead_size <= cache_size
    model = generate_markov_model(logfile_ref)
    cache = LRU(cache_size)
    hits = 0
    total = 0

    with open(logfile_pred, 'r') as f:
        while (addr := extract_page_access(f)) != None:
            if addr in cache:
                hits += 1
            else:
                cache[addr] = None
            
            ref_addr = addr
            for _ in range(lookahead_size):
                ref_addr = markov_select_next(model, ref_addr)
                if ref_addr is not None:
                    cache[ref_addr] = None
            total += 1
    return hits, total

def readahead_log_files(logfile_ref, logfile_pred, cache_size, lookahead_size):
    assert lookahead_size <= cache_size
    cache = LRU(cache_size)
    hits = 0
    total = 0

    with open(logfile_pred, 'r') as f:
        while (addr := extract_page_access(f)) != None:
            if addr in cache:
                hits += 1
            else:
                cache[addr] = None
            
            ref_addr = addr
            for i in range(lookahead_size):
                ref_addr = (addr[0], addr[1] + i)
                cache[ref_addr] = None
            total += 1
    return hits, total

def matching_log_files(logfile_ref, logfile_pred, cache_size, lookahead_size):
    assert lookahead_size <= cache_size
    cache = LRU(cache_size - lookahead_size)
    lookahead = LRU(lookahead_size)
    hits = 0
    total = 0

    with open(logfile_pred, 'r') as f, open(logfile_ref, 'r') as model:
        # Populate the first lookahead_size entries of the model into the cache
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


methods = {
    'readahead': readahead_log_files,
    'model': markov_model_log_files,
    'matching': matching_log_files
}


def resolve_log_file(path):
    cache_path = '.analysis_cache.' + os.path.basename(path)
    if os.path.exists(cache_path):
        print(f"Using cached log file at {cache_path}")
        return cache_path
    else:
        print(f"Resolving log file at {path} and caching to {cache_path}")
        # We keep only those lines that are page accesses, to speed up future runs
        with open(path, 'r') as src, open(cache_path, 'w') as dst:
            for line in src:
                if pattern.match(line):
                    dst.write(line)
        return cache_path

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Process a log of scheduler and page activity and compute metrics.')
    argparser.add_argument('method', type=str, help='The method to run, can be one of the following: ' + ','.join(methods.keys()))
    argparser.add_argument('logfile_ref', type=str, help='Path to the reference log file')
    argparser.add_argument('logfile_pred', type=str, help='Path to the predicted log file')
    argparser.add_argument('--size', type=int, default=1, help='Cache size in number of pages')
    argparser.add_argument('--lookahead', type=int, default=0, help='Lookahead size in number of pages')
    argparser.add_argument('--ignore-lru', action='store_true', help='If LRU is not available, use a set for the cache (for testing purposes)')

    args = argparser.parse_args()

    # Resolve file paths (possibly cached)
    args.logfile_ref = resolve_log_file(args.logfile_ref)
    args.logfile_pred = resolve_log_file(args.logfile_pred)

    hits, total = methods[args.method](
        args.logfile_ref, 
        args.logfile_pred,
        args.size,
        args.lookahead
    )

    print(f"Total accesses: {total}")
    print(f"Cache hits: {hits}")
    print(f"Hit rate: {hits / total:.2%}")