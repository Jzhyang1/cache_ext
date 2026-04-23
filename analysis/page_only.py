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

def hash_state(list_of_substates):
    # hash a list of substates into a single integer to save space in the Markov model
    h = 0
    for substate in list_of_substates:
        if substate is None:
            substate = 0
        h = (h * 1777 + substate) % 17777
    return h

def build_markov_model(logfile_ref, context_size, skip):
    # Build Markov model that includes the current and next PID in the state
    hist = {}
    prev_state = [None] * (context_size + skip)  # we will keep track of the last context_size states to use as the state for the Markov model
    with LogFileRead(logfile_ref) as f:
        for access in f:
            if access.type != 0:
                continue    # we only handle page-access events
            
            minihist = hist.setdefault(hash_state(prev_state), {})
            minihist[access.get_idx()] = minihist.get(access.get_idx(), 0) + 1
            # new state is the page index, the current PID, and the next PID
            partial_state = (access.get_idx() % 1777)
            prev_state = prev_state[1:] + [partial_state]
    model = {}
    for state, next_pages in hist.items():
        total = sum(next_pages.values())
        miniret = []
        for page, count in next_pages.items():
            prob = count / total
            if prob < 0.05:
                continue    # skip very unlikely transitions to save space
            miniret.append((page, prob))
        miniret.sort(key=lambda x: x[1], reverse=True)
        model[state[:context_size]] = miniret[:3]  # only keep the top 3 most likely next pages to save space
    return model

def predict_markov_next_page(model, current_state) -> int | None:
    # Given the current state, predict the next page index using the Markov model
    # returns a randomly sampled next page index
    current_state = hash_state(current_state)
    if current_state not in model:
        return None  # we have no data for this state
    next_pages = model[current_state]
    r = random.random()
    for page, prob in next_pages:
        if r < prob:
            return page
        r -= prob
    return predict_markov_next_page(model, current_state)  # in case of rounding errors


def page_only_markov_model_log_files(logfile_ref, logfile_pred, cache_size, lookahead_size, context_size):
    models = []
    for skip in range(lookahead_size):
        model = build_markov_model(logfile_ref, context_size, skip)
        print("model of size", len(model))
        models.append(model)
    
    hits, total = 0, 0
    with LogFileRead(logfile_pred) as f:
        prev_state = [None] * context_size
        cache = LRU(cache_size)
        for access in f:
            if access.type != 0:
                continue
            addr = access.get_idx()
            if addr in cache:
                hits += 1
            cache[addr] = cache.get(addr, 0) + 1
            state = (addr % 1777)

            prev_state = prev_state[1:] + [state]
            for skip in range(lookahead_size):
                model = models[skip]
                pred_addr = predict_markov_next_page(model, prev_state[skip:])
                if pred_addr is not None:
                    cache[pred_addr] = cache.get(pred_addr, 0) + 1
            total += 1

    print_hit_miss(hits, total)
    return hits, total

if __name__ == "__main__":
    parser = ArgumentParser(description='Evaluate a Markov model predictor on a log file')
    parser.add_argument('logfile_ref', help='log file to build the Markov model from')
    parser.add_argument('logfile_pred', help='log file to evaluate the Markov model on')
    parser.add_argument('--cache-size', '-c', type=int, default=3, help='size of the cache to simulate (0 for unlimited)')
    parser.add_argument('--lookahead-size', '-l', type=int, default=1, help='number of future accesses to predict and include in the cache')
    parser.add_argument('--context-size', '-t', type=int, default=3, help='number of past accesses to include in the state for the Markov model')
    args = parser.parse_args()

    page_only_markov_model_log_files(args.logfile_ref, args.logfile_pred, args.cache_size, args.lookahead_size, args.context_size)