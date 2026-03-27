# Code to split large log files into logs containing only
# relevant page accesses by some PIDs

def cache_log_file(logfile, pid_admit_set: set[int]):
    '''
    reads logfile and takes those page accesses associated with relevant pids and stores
    it into <logfile>.<pid>.log
    '''
    from compare import LogFileRead, LogFileWrite

    joined = '.'.join(map(str, sorted(pid_admit_set)))
    logfile_cache = f'{logfile}.{joined}.log'
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

def first_instance_of_pid(logfile, pids: set[int]):
    from compare import LogFileRead
    with LogFileRead(logfile) as f:
        firsts: dict[int, int | None] = {pid: None for pid in pids}
        for access in f:
            if access.page_index in pids and firsts[access.page_index] is None:
                firsts[access.page_index] = access.nr_event
        return firsts

def last_instance_of_pid(logfile, pids: set[int]):
    from compare import LogFileRead
    with LogFileRead(logfile) as f:
        lasts: dict[int, int | None] = {pid: None for pid in pids}
        for access in f:
            if access.page_index in pids:
                lasts[access.page_index] = access.nr_event
        return lasts

ops = {
    'cache': cache_log_file,
    'first': first_instance_of_pid,
    'last': last_instance_of_pid,
}

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Cache log file by PIDs')
    parser.add_argument('operation', type=str, choices=ops.keys(), help='operation to perform')
    parser.add_argument('logfile', type=str, help='log file to cache')
    parser.add_argument('pids', type=int, nargs='+', help='PIDs to admit')
    args = parser.parse_args()

    if args.operation == 'cache':
        cache_log_file(args.logfile, set(map(int, args.pids)))
    else:
        result = ops[args.operation](args.logfile, set(map(int, args.pids)))
        for pid, event in result.items():
            print(f'{args.operation} of PID {pid}: {event}')