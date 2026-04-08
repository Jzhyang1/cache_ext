import logging
import os
from time import time
from typing import List, Dict

from bench_lib import *

log = logging.getLogger(__name__)

# These only run on error
CLEANUP_TASKS = []


class FileSearchBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("filesearch_benchmark", benchresults_cls, cli_args)
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, 
            self.args.policy_loader, 
            self.args.data_dir
        )
        CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--data-dir",
            type=str,
            required=True,
            help="Data directory",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            required=True,
            help="Specify the path to the policy loader binary",
        )
        parser.add_argument(
            "--scan-util-path",
            type=str,
            required=True,
            help="Path to the scan util binary",
        )
        parser.add_argument(
            "--reverse",
            "-r",
            type=bool,
            default=False,
            help="Whether to do reverse scans in files (i.e. read bytes in reverse order)",
        )
        parser.add_argument(
            "--pages",
            type=str,
            default="77",
            help="Comma-separated list of page offsets to repeatedly hit in the files (default: 77)",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("passes", [10], configs)
        configs = add_config_option("cgroup_size", [1 * GiB], configs)
    
        configs = add_config_option(
            "cgroup_name",
            [DEFAULT_CACHE_EXT_CGROUP],
            configs,
        )

        configs = add_config_option("benchmark", ["filesearch"], configs)
        configs = add_config_option(
            "iteration", list(range(1, self.args.iterations + 1)), configs
        )
        configs = add_config_option(
            "page_indices", [self.args.pages], configs,
        )
        return configs

    def benchmark_prepare(self, config):
        drop_page_cache()
        disable_swap()
        disable_smt()
        recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])

    def before_benchmark(self, config):
        self.cache_ext_policy.start(
            "filesearch_benchmark", 
            cgroup_size=config["cgroup_size"],
            process_pids=config.get("process_pids", [])
        )
        self.start_time = time()

    def benchmark_cmd(self, config):
        scan_util = self.args.scan_util_path
        data_dir = self.args.data_dir
        reverse = self.args.reverse
        cmd = [
            "sudo",
            "cgexec",
            "-g",
            "memory:%s" % config["cgroup_name"],
            scan_util,
        ]
        if reverse:
            cmd += ["-r"]
        cmd += [
            data_dir
        ]

        page_indices = config["page_indices"].split(",")
        return [cmd + [page_index] for page_index in page_indices]

    def after_benchmark(self, config):
        self.end_time = time()
        self.cache_ext_policy.stop()
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = {"runtime_sec": self.end_time - self.start_time}
        return BenchResults(results)


def main():
    global log
    logging.basicConfig(level=logging.DEBUG)
    global log
    # To ensure that writeback keeps up with the benchmark
    filesearch_bench = FileSearchBenchmark()
    # Check that trace data dir exists
    if not os.path.exists(filesearch_bench.args.data_dir):
        raise Exception(
            "Filesearch data directory not found: %s" % filesearch_bench.args.data_dir
        )
    log.info("Filesearch data directory: %s", filesearch_bench.args.data_dir)
    filesearch_bench.benchmark()


if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.INFO)
        main()
    except Exception as e:
        log.error("Error in main: %s", e)
        log.info("Cleaning up")
        for task in CLEANUP_TASKS:
            task()
        log.error("Re-raising exception")
        raise e
