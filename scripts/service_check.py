#!/usr/bin/env python3
"""Check native Veil onion hosting against an isolated C Tor network and client."""
import argparse
import os
import pathlib
import subprocess
import sys

from proxy_demo import executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tor", default=os.environ.get("TOR"))
    parser.add_argument("--tor-gencert", default=os.environ.get("TOR_GENCERT"))
    args = parser.parse_args()
    tor = executable(args.tor, "tor", "tor-*/src/app/tor")
    gencert = executable(args.tor_gencert, "tor-gencert", "tor-*/src/tools/tor-gencert")
    root = pathlib.Path(__file__).resolve().parent.parent
    print("Building Veil and the private onion-hosting test; network bootstrap may take four minutes.", flush=True)
    subprocess.run(["go", "build", "-trimpath", "-o", "bin/veil", "./cmd/veil"], cwd=root, check=True)
    subprocess.run(["go", "test", "-tags", "veiltest", "-c", "-race", "-o", "bin/service-test", "./service"], cwd=root, check=True)
    subprocess.run([sys.executable, "scripts/check_local_directory.py", "--tor", tor, "--gencert", gencert, "--veil", "bin/veil", "--service-test", "bin/service-test"], cwd=root, check=True)


if __name__ == "__main__":
    main()
