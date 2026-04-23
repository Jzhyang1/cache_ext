from argparse import ArgumentParser

from sim import run_simulation, Prefetcher, LogEntry

class DeltaChainPrefetcher(Prefetcher):
    """
    An online prefetcher that looks for repeating sequences of deltas.
    Example: Pattern +4, +8, +4, +8... 
    When it sees +4, it predicts the next jump is +8.
    """
    def __init__(self, history_size, lookahead, differentiate_pids, friendly_eager):
        self.last_address = {}
        self.delta_history = {} # Stores recent deltas per PID
        self.history_size = history_size
        self.lookahead = lookahead
        self.differentiate_pids = differentiate_pids
        self.friendly_eager = friendly_eager # prefetches the next page for the next PID scheduled

    def on_access(self, access: LogEntry, cache_manager):
        pid_self = access.pid_self if self.differentiate_pids else 0

        if self.last_address.get(pid_self) is not None:
            current_delta = access.get_idx() - self.last_address[pid_self]

            # 2. Search for the current delta in our history to find a "chain"
            # We look for the last occurrence of this delta to see what followed it
            predictions = self._predict_next_deltas(self.delta_history.get(pid_self, []), current_delta)
            for prediction in predictions:
                # We predict based on the correlated history
                cache_manager.fetch(access.get_idx() + prediction)

            # 2.5 If friendly eager, also prefetch the next page for the next PID scheduled
            if self.friendly_eager:    # this will only happen if we differentiate PIDs
                friend_pid = access.pid_next
                predictions = self._predict_next_deltas(self.delta_history.get(friend_pid, []), current_delta)
                for prediction in predictions:
                    cache_manager.fetch(access.get_idx() + prediction)

            # 3. Update history
            self.delta_history.setdefault(pid_self, []).append(current_delta)
            if len(self.delta_history[pid_self]) > self.history_size:
                self.delta_history[pid_self].pop(0)

        self.last_address[pid_self] = access.get_idx()

    def _predict_next_deltas(self, delta_history, current_delta):
        """
        Looks back through history. If we find current_delta, 
        return the delta that followed it last time.
        """
        # Search backwards (excluding the most recent entry we haven't added yet)
        for i in range(len(delta_history) - 1, 0, -1):
            if delta_history[i-1] == current_delta:
                return delta_history[i:i+self.lookahead] # Return the next few deltas as predictions
        return []
    
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
    policy = DeltaChainPrefetcher(args.context_size, args.readahead_size, differentiate_pids=args.differentiate_pids, friendly_eager=args.friendly_eager)
    
    # Run
    run_simulation(args.logfile_pred, policy, args.cache_size, args.max_steps)