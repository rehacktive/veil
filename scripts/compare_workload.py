#!/usr/bin/env python3
"""Build and run the private matched-workload comparison. No public traffic."""
import argparse
import pathlib
import subprocess
import sys
from proxy_demo import executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tor")
    parser.add_argument("--tor-gencert")
    parser.add_argument("--report", required=True, type=pathlib.Path)
    parser.add_argument("--samples", type=int, default=3, choices=range(1, 11))
    parser.add_argument("--idle", type=int, default=60, choices=range(10, 301))
    args = parser.parse_args()
    tor = executable(args.tor, "tor", "tor-*/src/app/tor")
    gencert = executable(args.tor_gencert, "tor-gencert", "tor-*/src/tools/tor-gencert")
    root = pathlib.Path(__file__).resolve().parent.parent
    subprocess.run(["go", "build", "-tags", "veiltraffic", "-trimpath", "-o", "bin/veil-traffic", "./cmd/veil"], cwd=root, check=True)
    subprocess.run([sys.executable, "scripts/check_local_directory.py", "--tor", tor, "--gencert", gencert,
                    "--veil", "bin/veil-traffic", "--workload-report", str(args.report.resolve()),
                    "--workload-samples", str(args.samples), "--workload-idle", str(args.idle)], cwd=root, check=True)


if __name__ == "__main__":
    main()
