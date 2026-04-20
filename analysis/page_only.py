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


def build_markov_model(logfile_ref, context_size):
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
        total = sum(entries.values())
        accum, miniret = 0, []
        for next_addr, count in entries.items():
            accum += count
            miniret.append((accum/total, next_addr))
        ret[addr] = miniret
    print("model is of size", len(ret))
    return ret

def predict_markov_next_page(model, current_state):
    # Given the current state, predict the next page index using the Markov model
    # returns a randomly sampled next page index
    if current_state not in model:
        return None  # we have no data for this state
    next_pages = model[current_state]
    r = random.random()
    for page, accum_prob in next_pages:
        if r < accum_prob:
            return page
    return predict_markov_next_page(model, current_state)  # in case of rounding errors, resample


def page_only_markov_model_log_files(logfile_ref, logfile_pred, cache_size, lookahead_size, context_size):
    assert lookahead_size == 1
    model = build_markov_model(logfile_ref, context_size)
    print("model is size", len(model))
    
    hits, total = 0, 0
    with LogFileRead(logfile_pred) as f:
        prev_state = [None] * context_size
        cache = LRU(cache_size)
        for access in f:
            if access.type != 0:
                continue
            addr = access.page_index
            if addr in cache:
                cache[addr] = cache.get(addr, 0) + 1
                hits += 1
            state = (addr)

            prev_state = prev_state[1:] + [state]
            pred_addr = predict_markov_next_page(model, tuple(prev_state))
            if pred_addr is not None:
                cache[pred_addr] = cache.get(pred_addr, 0) + 1
            total += 1

    print_hit_miss(hits, total)

if __name__ == "__main__":
    parser = ArgumentParser(description='Evaluate a Markov model predictor on a log file')
    parser.add_argument('logfile_ref', help='log file to build the Markov model from')
    parser.add_argument('logfile_pred', help='log file to evaluate the Markov model on')
    parser.add_argument('--cache-size', '-c', type=int, default=3, help='size of the cache to simulate (0 for unlimited)')
    parser.add_argument('--lookahead-size', '-l', type=int, default=1, help='number of future accesses to predict and include in the cache')
    parser.add_argument('--context-size', '-t', type=int, default=3, help='number of past accesses to include in the state for the Markov model')
    args = parser.parse_args()

    page_only_markov_model_log_files(args.logfile_ref, args.logfile_pred, args.cache_size, args.lookahead_size, args.context_size)