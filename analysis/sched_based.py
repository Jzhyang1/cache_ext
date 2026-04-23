import os
import random
import sys
from argparse import ArgumentParser

# Adds the directory containing this file to the search path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from compare import LogFileRead, print_hit_miss
from lru import LRU

def hash_state(list_of_substates):
    # hash a list of substates into a single integer to save space in the Markov model
    h = 0
    for substate in list_of_substates:
        if substate is None:
            substate = 0
        h = (h * 1777 + substate) % 177777
    return h

def build_markov_model(logfile_ref, context_size, skip, max_steps):
    # Build Markov model that includes the current and next PID in the state
    hist = {}
    prev_state = [None] * (context_size + skip)  # we will keep track of the last context_size states to use as the state for the Markov model
    with LogFileRead(logfile_ref) as f:
        steps = 0
        for access in f:
            if access.type != 0:
                continue    # we only handle page-access events
            if (steps := steps + 1) > max_steps:
                break
            
            minihist = hist.setdefault(hash_state(prev_state[:context_size]), {})
            minihist[access.get_idx()] = minihist.get(access.get_idx(), 0) + 1
            # new state is the page index, the current PID, and the next PID
            # do some hashing to save space
            partial_state = access.get_idx() % 1777 + (access.pid_self ^ access.pid_next)
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
        model[state] = miniret[:3]  # only keep the top 3 most likely next pages to save space
    return model

def predict_markov_next_page(model, current_state) -> int | None:
    # Given the current state, predict the next page index using the Markov model
    # returns a randomly sampled next page index
    current_state = hash_state(current_state)
    if current_state not in model:
        return None  # we have no data for this state
    next_pages = model[current_state]
    r = random.random()
    while True:
        for page, prob in next_pages:
            if r < prob:
                return page
            r -= prob
        r = random.random()


def sched_aware_markov_model_log_file(logfile_ref, logfile_pred, cache_size, lookahead_size, context_size, max_steps):
    models = []
    for skip in range(lookahead_size):
        model = build_markov_model(logfile_ref, context_size, skip, max_steps)
        print("model of size", len(model))
        models.append(model)

    hits, total = 0, 0
    with LogFileRead(logfile_pred) as f:
        prev_state = [None] * context_size
        cache = LRU(cache_size)
        steps = 0
        for access in f:
            if access.type != 0:
                continue
            if (steps := steps + 1) > max_steps:
                break

            addr = access.get_idx()
            if addr in cache:
                hits += 1
            cache[addr] = cache.get(addr, 0) + 1
            state = addr % 1777 + (access.pid_self ^ access.pid_next)

            prev_state = prev_state[1:] + [state]
            for skip in range(lookahead_size):
                model = models[skip]
                pred_addr = predict_markov_next_page(model, prev_state[skip:])
                if pred_addr is not None:
                    cache[pred_addr] = cache.get(pred_addr, 0) + 1
            total += 1

    print_hit_miss(hits, total)
    return hits, total

if __name__ == '__main__':
    parser = ArgumentParser(description='Evaluate a Markov model predictor on a log file')
    parser.add_argument('logfile_ref', help='log file to build the Markov model from')
    parser.add_argument('logfile_pred', help='log file to evaluate the Markov model on')
    parser.add_argument('--cache-size', '-c', type=int, default=3, help='size of the cache to simulate (0 for unlimited)')
    parser.add_argument('--lookahead-size', '-l', type=int, default=1, help='number of future accesses to predict and include in the cache')
    parser.add_argument('--context-size', '-t', type=int, default=3, help='number of past accesses to include in the state for the Markov model')
    parser.add_argument('--max-steps', '-s', type=int, default=600000, help='maximum number of steps to process')
    args = parser.parse_args()

    sched_aware_markov_model_log_file(args.logfile_ref, args.logfile_pred, args.cache_size, args.lookahead_size, args.context_size, args.max_steps)