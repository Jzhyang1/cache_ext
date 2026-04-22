import os
import random
import sys
from argparse import ArgumentParser

# Adds the directory containing this file to the search path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from page_only import page_only_markov_model_log_files
from sched_based import sched_aware_markov_model_log_file

# We allow configuration of the context-size and lookahead-size,
# we do a 2-pointer search to find the approximate cache-sizes at which
# the two models perform similarly, we continue until one model reaches
# a maximum cache size (configurable)

initial_cache_size = 4
cache_size_increment = 4

def all_sim(logfile_ref, logfile_pred, max_cache_size, lookahead_size, context_size):
    hit_rate_page_only = [(0.0, initial_cache_size)]
    hit_rate_sched_aware = [(0.0, initial_cache_size)]

    while hit_rate_page_only[-1][1] < max_cache_size and hit_rate_sched_aware[-1][1] < max_cache_size:
        if hit_rate_page_only[-1][0] <= hit_rate_sched_aware[-1][0]:
            cache_size = hit_rate_page_only[-1][1] + cache_size_increment
            hits_page_only, total_page_only = page_only_markov_model_log_files(logfile_ref, logfile_pred, cache_size, lookahead_size, context_size)
            hit_rate_page_only.append((hits_page_only / total_page_only, cache_size))
            print(f"Page-only model: {hits_page_only}/{total_page_only} hits (cache size {cache_size})")
        if hit_rate_sched_aware[-1][0] <= hit_rate_page_only[-1][0]:
            cache_size = hit_rate_sched_aware[-1][1] + cache_size_increment
            hits_sched_aware, total_sched_aware = sched_aware_markov_model_log_file(logfile_ref, logfile_pred, cache_size, lookahead_size, context_size)
            hit_rate_sched_aware.append((hits_sched_aware / total_sched_aware, cache_size))
            print(f"Sched-aware model: {hits_sched_aware}/{total_sched_aware} hits (cache size {cache_size})")
        print()

    print("Final results:")
    print("Page-only model:")
    for hit_rate, cache_size in hit_rate_page_only:
        print(f"  Cache size {cache_size}: {hit_rate:.2%}")
    print("Sched-aware model:")
    for hit_rate, cache_size in hit_rate_sched_aware:
        print(f"  Cache size {cache_size}: {hit_rate:.2%}")

    # save a graph
    from matplotlib import pyplot as plt
    plt.plot([cache_size for _, cache_size in hit_rate_page_only], [hit_rate for hit_rate, _ in hit_rate_page_only], label="Page-only model")
    plt.plot([cache_size for _, cache_size in hit_rate_sched_aware], [hit_rate for hit_rate, _ in hit_rate_sched_aware], label="Sched-aware model")
    plt.xlabel("Cache Size")
    plt.ylabel("Hit Rate")
    plt.title("Performance Comparison")
    plt.legend()
    plt.show()

    return hit_rate_page_only, hit_rate_sched_aware

if __name__ == "__main__":
    parser = ArgumentParser(description='Compare the performance of page-only and sched-aware Markov models on log files')
    parser.add_argument('logfile_ref', help='The reference log file to build the Markov model from')
    parser.add_argument('logfile_pred', help='The log file to evaluate the Markov model on')
    parser.add_argument('--max_cache_size', type=int, default=64, help='The maximum cache size to evaluate up to')
    parser.add_argument('--lookahead_size', type=int, default=4, help='The lookahead size for the Markov model')
    parser.add_argument('--context_size', type=int, default=2, help='The context size for the Markov model')
    args = parser.parse_args()

    all_sim(args.logfile_ref, args.logfile_pred, args.max_cache_size, args.lookahead_size, args.context_size)