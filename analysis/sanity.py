

import os
import sys
from argparse import ArgumentParser

# Adds the directory containing this file to the search path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from compare import LogFileRead

def sanity_check(logfile):
    start_n, cur_n, count = None, 0, 0  # the ordering numbers of the events for drop count
    source_says = 0     # the number of drops counted by kernel
    
    sched_events, page_access_events = 0, 0

    active_pids = set() # PIDs in runqueue based on sched logs
    pid_access_not_active = 0 # Count accesses where the pid_self is not in active_pids, which shouldn't happen

    pid_nexts = []      # Assume that the runqueue doesn't change 
    pid_matched_to = 0  #  then we can go through the pid_nexts and match to each sched interrupt
    with LogFileRead(logfile) as f:
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
                    print("accessing", access.pid_self, "which is not active in", active_pids)
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
    print(f"Scheduler consistent with {pid_matched_to} of {len(pid_nexts)} ({pid_matched_to/len(pid_nexts) if pid_nexts else 0:.2%}) of page accesses")
    print(f"Accesses with non-active PIDs: {pid_access_not_active} of {page_access_events} ({pid_access_not_active / page_access_events if page_access_events > 0 else 0:.2%})")

if __name__ == '__main__':
    parser = ArgumentParser(description='Sanity check for log files')
    parser.add_argument('logfile', help='log file to check')
    args = parser.parse_args()
    sanity_check(args.logfile)