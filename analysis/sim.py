import os
import sys
from argparse import ArgumentParser

# Setup pathing
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from lru import LRU


class LogEntry:
    # every log entry is a 40-byte struct
    # 0-8: nr_event
    # 8-12: type (always 0)
    # 12-16: drop_count
    # 16-24: address_space
    # 24-32: page_index
    # 32-36: pid_self
    # 36-40: pid_next
    def __init__(self, nr_event, type, drop_count, address_space, page_index, pid_self, pid_next):
        self.nr_event = nr_event
        self.type = type
        self.drop_count = drop_count
        self.address_space = address_space
        self._page_index = page_index
        self.sched_pid_prev = address_space
        self.sched_pid_next = page_index
        self.pid_self = pid_self
        self.pid_next = pid_next
    def get_idx(self):
        return self.address_space * 10000 + self._page_index
class LogFileIterator:
    def __init__(self, file):
        self.file = file
    
    def __iter__(self):
        return self
    
    def __next__(self):
        data = self.file.read(40)
        if not data:
            raise StopIteration
        nr_event = int.from_bytes(data[0:8], 'little')
        type = int.from_bytes(data[8:12], 'little')
        drop_count = int.from_bytes(data[12:16], 'little')
        address_space = int.from_bytes(data[16:24], 'little')
        page_index = int.from_bytes(data[24:32], 'little')
        pid_self = int.from_bytes(data[32:36], 'little')
        pid_next = int.from_bytes(data[36:40], 'little')
        return LogEntry(nr_event, type, drop_count, address_space, page_index, pid_self, pid_next)

class LogFileRead:
    def __init__(self, path):
        self.path = path
        self.file = None
    def __enter__(self):
        self.file = open(self.path, 'rb')
        # return an iterable over the log entries
        return LogFileIterator(self.file)
    def __exit__(self, exc_type, exc_value, traceback):
        if self.file is not None:
            self.file.close()

class CacheManager:
    """Manages the LRU cache state and tracks performance metrics."""
    def __init__(self, cache_size):
        self.cache = LRU(cache_size)
        self.hits = 0
        self.page_ins = 0
        self.total_accesses = 0

    def access(self, address):
        """Simulates a demand access for a page."""
        self.total_accesses += 1
        
        if address in self.cache:
            self.hits += 1
        
        # We perform the actual fetch (or update LRU position)
        self.fetch(address)

    def fetch(self, address):
        """Internal method to bring a page into cache if not present."""
        if address not in self.cache:
            self.page_ins += 1
            self.cache[address] = 1
        else:
            # Update frequency/recency
            self.cache[address] += 1

    def report(self):
        """Prints the simulation results."""
        print(f"Page-ins: {self.page_ins}, "
              f"this is {self.page_ins / self.total_accesses * 100:.2f}% of total accesses")
        print(f"Total accesses: {self.total_accesses}")
        print(f"Cache hits: {self.hits}, "
              f"this is {self.hits / self.total_accesses * 100:.2f}% of total accesses")


# ------------------------------------------------------------------

class Prefetcher:
    """Base class for prefetchers."""
    def on_access(self, access: LogEntry, cache_manager: CacheManager):
        pass

class ReadaheadPrefetcher(Prefetcher):
    """Implements a standard sequential readahead policy."""
    def __init__(self, readahead_size):
        self.readahead_size = readahead_size

    def on_access(self, access: LogEntry, cache_manager: CacheManager):
        # 2. Perform the readahead prefetching
        for i in range(1, self.readahead_size + 1):
            cache_manager.fetch(access.get_idx() + i)


def run_simulation(logfile_path, prefetcher: Prefetcher, cache_size, max_steps):
    """Orchestrates the simulation loop."""
    manager = CacheManager(cache_size)
    
    with LogFileRead(logfile_path) as f:
        for i, access in enumerate(f):
            if i >= max_steps:
                break
            # Filter for page access types (type 0)
            if access.type != 0:
                continue

            manager.access(access.get_idx())
            prefetcher.on_access(access, manager)
    manager.report()


if __name__ == "__main__":
    parser = ArgumentParser(description='Evaluate a prefetching policy on a log file')
    parser.add_argument('logfile_pred', help='log file to evaluate')
    parser.add_argument('--cache-size', '-c', type=int, default=3)
    parser.add_argument('--readahead-size', '-l', type=int, default=0)
    parser.add_argument('--max-steps', type=int, default=1000000000)
    args = parser.parse_args()

    # Initialize the policy
    policy = ReadaheadPrefetcher(args.readahead_size)
    
    # Run
    run_simulation(args.logfile_pred, policy, args.cache_size, args.max_steps)