import os
import sys
import subprocess
import argparse
from typing import List, Dict

# We only parse these arguments:
#  "--policy-path"
#  "--policies" 
#  "--bench-file"
parser = argparse.ArgumentParser()
parser.add_argument(
    "--policy-path",
    type=str,
    required=True,
    help="Path to the directory containing policy loader binaries.",
)
parser.add_argument(
    "--policies",
    type=str,
    required=True,
    help="Comma or space-separated list of cache policies to benchmark.",
)
parser.add_argument(
    "--bench-file",
    type=str,
    required=True,
    help="Path to the benchmark file to run.",
)
args, unknown = parser.parse_known_args()
policies = [p.strip() for p in args.policies.replace(",", " ").split()]

for policy in policies:
    cmd = [
        sys.executable,
        args.bench_file,
        "--policy-loader",
        os.path.join(args.policy_path, f"{policy}.out"),
    ] + unknown
    print(f"Running benchmark with policy: {policy}")
    print(f"Command: {' '.join(cmd)}")
    result = subprocess.run(cmd, stderr=subprocess.PIPE)
    if result.returncode != 0:
        print(f"Benchmark with policy {policy} failed.", file=sys.stderr)
        print(result.stderr.decode(), file=sys.stderr)
    # Continue to next policy even if one fails