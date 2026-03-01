#!/bin/python

# This simulates running all the processes in the log file
# and pools the page access events w.r.t the processes that
# were running when the page access happened.

# Every page access gives 1/n 'score' to the (pid, address_space)
# combination, where n is the number of running processes

# Calculates a metric comparing how unevenly distributed the
# page accesses are compared to every page access given to
# every process that is "alive" with 1/m where m is all alive processes

# We call a process "alive" at a time if it has been scheduled once 
# in the last A processes and is scheduled again in the next B processes

# The MSE between the first and second 'scores' measures on average
# how much more likely we are to hit a page access by fetching via 'scheduled'
# v.s. fetching with only knowledge of 'alive'

import argparse
import re

# Arguments to the program:
# check.py <logfile> <A> <B>

argparser = argparse.ArgumentParser(description='Process a log of scheduler and page activity and compute metrics.')
argparser.add_argument('logfile', type=str, help='Path to the log file')
argparser.add_argument('A', type=int, help='Number of past processes to consider for "alive" status')
argparser.add_argument('B', type=int, help='Number of future processes to consider for "alive" status')

args = argparser.parse_args()
logfile = args.logfile
A = args.A
B = args.B

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

# Metric and data tracking
running_scores = {}
alive_scores = {}
running_pids = set()
alive_pids = {} 

# We use a circular buffer
track_alive_pids = [0] * (A + B)
split = A

with open(logfile, "r") as f:
    pattern1 = re.compile(r'(\d+): Page Access - Address Space: (\d+), Page Index: (\d+), Timestamp: (\d+)')
    pattern2 = re.compile(r'(\d+): Sched Switch - Prev PID: (\d+), Next PID: (\d+), Timestamp: (\d+)')
    for line in f:
        if pat := pattern1.match(line):
            addr_space, page = pat.group(2), pat.group(3)
            n = len(running_pids)
            for pid in running_pids:
                idx = (pid, addr_space, page)
                running_scores[idx] = running_scores.get(idx, 0) + 1/n
            for pid in alive_pids:
                idx = (pid, addr_space, page)
                alive_scores[idx] = alive_scores.get(idx, 0) + 1/n
        elif pat := pattern2.match(line):
            prev, nxt = pat.group(2), pat.group(3)
            if prev in running_pids: running_pids.remove(prev)
            running_pids.add(nxt)

            evict_idx = (split + B)%(A+B)
            cnt = alive_pids.get(evict_idx, 0) - 1
            if cnt - 1 == 0:
                candidate = track_alive_pids[evict_idx]
                del alive_pids[candidate]
            track_alive_pids[evict_idx] = nxt
            alive_pids[nxt] = alive_pids.get(nxt, 0) + 1
        else:
            perror("No match found for", line)

