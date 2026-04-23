from argparse import ArgumentParser

from sim import run_simulation, Prefetcher, LogEntry

class AMPMPrefetcher(Prefetcher):
    """
    Access Map Pattern Matching (AMPM) Prefetcher.
    Divides memory into 'regions' and tracks access bitmasks.
    Highest accuracy among classical pattern-matching prefetchers.
    """
    def __init__(self, region_size, degree):
        self.regions = {}  # {region_id: bitmask_list}
        self.region_size = region_size
        self.degree = degree

    def on_access(self, access: LogEntry, cache_manager):
        address = access.get_idx()

        # 2. Identify Region
        region_id = address // self.region_size
        offset = address % self.region_size
        
        if region_id not in self.regions:
            self.regions[region_id] = [0] * self.region_size
        
        # Mark current page as accessed
        self.regions[region_id][offset] = 1
        
        # 3. Pattern Recognition Logic
        # We look for 'strides' that are consistently present in the current region
        for stride in range(-16, 17):
            if stride == 0: continue
            
            # Check if (offset - stride) and (offset - 2*stride) were accessed
            # This indicates a consistent geometric pattern in this region
            if self._is_accessed(region_id, offset - stride) and \
               self._is_accessed(region_id, offset - 2 * stride):
                
                # We found a pattern! Prefetch the next 'degree' steps
                for d in range(1, self.degree + 1):
                    prefetch_addr = address + (stride * d)
                    cache_manager.fetch(prefetch_addr)

    def _is_accessed(self, region_id, offset):
        if 0 <= offset < self.region_size:
            return self.regions[region_id][offset] == 1
        return False
    
if __name__ == "__main__":
    parser = ArgumentParser(description='Evaluate a prefetching policy on a log file')
    parser.add_argument('logfile_pred', help='log file to evaluate')
    parser.add_argument('--cache-size', '-c', type=int, default=10)
    parser.add_argument('--readahead-size', '-l', type=int, default=2)
    parser.add_argument('--context-size', '-s', type=int, default=16)
    parser.add_argument('--max-steps', '-m', type=int, default=1000000000)
    parser.add_argument('--differentiate-pids', '-d', action='store_true', help='Keep separate histories per PID')
    parser.add_argument('--friendly-eager', '-f', action='store_true', help='Prefetch the next page for the next PID scheduled')
    args = parser.parse_args()

    if args.friendly_eager and not args.differentiate_pids:
        print("Warning: Friendly eager prefetching is enabled without differentiating PIDs. This may lead to less accurate predictions.")

    # Initialize the policy
    policy = AMPMPrefetcher(args.context_size, args.readahead_size)
    
    # Run
    run_simulation(args.logfile_pred, policy, args.cache_size, args.max_steps)