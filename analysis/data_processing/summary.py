#!/usr/bin/python3

# We accept a log file and any number of PIDs and generate a summary of the cache hits and misses
# Using a model of the log file on itself (see compare.py), segregated models
# on their on log files (by PID - see compare.py), and a histogram of the page
# indices (see hist.py)

from compare import markov_model_log_files, LogFileRead
from cache import cache_log_file
from hist import plot
from argparse import ArgumentParser

if __name__ == '__main__':
    parser = ArgumentParser(description='Generate summary from log file')
    parser.add_argument('file', help='log file to read')
    parser.add_argument('pids', nargs='+', type=int, help='PIDs to analyze')
    args = parser.parse_args()

    logfile = args.file
    pids = args.pids

    # Generate the cache model for the specified PIDs
    pids = set(pids)
    logfile_all = cache_log_file(logfile, pids)
    logfile_each = []
    for pid in pids:
        logfile_each.append(cache_log_file(logfile, {pid}))

    # Generate the Markov model for the entire log file
    print("[All]")
    markov_model_log_files(logfile_all, logfile_all, 0, 1, 1)

    # Generate the Markov model for each PID predicting each PID
    for i, pid_ref in enumerate(pids):
        for j, pid_pred in enumerate(pids):
            print(f"[PID {pid_ref} vs PID {pid_pred}]")
            markov_model_log_files(logfile_each[i], logfile_each[j], 0, 1, 1)

    # Generate the histogram of page indices for each PID
    for page_accesses in logfile_each:
        data = []
        with LogFileRead(page_accesses) as f:
            for line in f:
                data.append(line._page_index)
        plot(page_accesses, data)