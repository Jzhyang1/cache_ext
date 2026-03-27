# Code to split large log files into logs containing only
# relevant page accesses by some PIDs

def cache_log_file(logfile, pid_admit_set: set[int]):
    '''
    reads logfile and takes those page accesses associated with relevant pids and stores
    it into <logfile>.<pid>.log
    '''
    from compare import LogFileRead, LogFileWrite

    joined = '.'.join(map(str, sorted(pid_admit_set)))
    logfile_cache = f'{logfile}.{joined}'
    with LogFileRead(logfile) as f, LogFileWrite(logfile_cache) as g:
        active_count = 0    # TODO this assumes all PIDs have 1 thread
        for access in f:
            if access.type == 1:
                if access.address_space in pid_admit_set:
                    active_count = max(0, active_count - 1)
                if access.page_index in pid_admit_set:
                    active_count += 1
            elif access.type == 0:
                if active_count > 0:
                    g(access.nr_event, access.type, access.drop_count, access.address_space, access.page_index)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Cache log file by PIDs')
    parser.add_argument('logfile', type=str, help='log file to cache')
    parser.add_argument('pids', type=int, nargs='+', help='PIDs to admit')
    args = parser.parse_args()
    cache_log_file(args.logfile, set(map(int, args.pids)))