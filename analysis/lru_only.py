import os
import random
import sys
from argparse import ArgumentParser

# Adds the directory containing this file to the search path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from compare import LogFileRead, print_hit_miss
from lru import LRU

# The program uses the page accesses from logfile_ref to model how well the prefetcher can
# perform with knowledge of the future page accesses on a different log logfile_pred.
# Eviction is performed using LRU

def lru_only_log_files(logfile_pred, cache_size, readahead_size):
    page_ins, hits, total = 0, 0, 0
    with LogFileRead(logfile_pred) as f:
        cache = LRU(cache_size)
        for access in f:
            if access.type != 0:
                continue
            addr = access.page_index
            if addr in cache:
                hits += 1
            else:
                page_ins += 1
            
            for i in range(readahead_size + 1):
                count = cache.get(addr + i, 0)
                if count == 0:
                    # not in cache, page it in
                    page_ins += 1
                # make the accessed pages more recently used
                cache[addr + i] = count + 1
            total += 1

    print(f"Page-ins: {page_ins}, this is {page_ins / total * 100:.2f}% of total accesses")
    print_hit_miss(hits, total)

if __name__ == "__main__":
    parser = ArgumentParser(description='Evaluate a Markov model predictor on a log file')
    parser.add_argument('logfile_ref', help='log file to build the Markov model from')
    parser.add_argument('logfile_pred', help='log file to evaluate the Markov model on')
    parser.add_argument('--cache-size', '-c', type=int, default=3, help='size of the cache to simulate')
    parser.add_argument('--readahead-size', '-l', type=int, default=0, help='number of consecutive-pages to prefetch on an access')
    args = parser.parse_args()

    lru_only_log_files(args.logfile_pred, args.cache_size, args.readahead_size)