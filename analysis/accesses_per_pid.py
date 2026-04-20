import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from compare import LogFileRead

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Generate histogram of page accesses per PID')
    parser.add_argument('logfile', help='log file to read')
    parser.add_argument('--bins', type=int, default=50, help='number of bins in histogram')
    args = parser.parse_args()

    with LogFileRead(args.logfile) as f:
        cur_pid = None
        cur_run = 0
        tallies = []
        for access in f:
            if access.type == 0:  # only count page-access events
                if cur_pid != access.pid_self:
                    tallies.append(cur_run)
                    cur_pid = access.pid_self
                    cur_run = 0
                cur_run += 1
        tallies.append(cur_run)  # add the last run

    # print median
    print("median:", sorted(tallies)[len(tallies) // 2])

    from hist import plot
    plot(args.logfile, tallies, bins=args.bins)