#!/usr/bin/env python3
"""Build and launch a private Veil SOCKS5/curl demo (no public Tor traffic)."""
import argparse
import os
import pathlib
import shutil
import subprocess
import sys


def executable(explicit, name, pattern):
    if explicit:
        candidates = [pathlib.Path(explicit)]
    else:
        found = shutil.which(name)
        candidates = [pathlib.Path(found)] if found else []
        candidates += sorted(pathlib.Path("/private/tmp/go-arti-tor-build").glob(pattern), reverse=True)
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate.resolve())
    raise SystemExit(f"Cannot find {name}. Install C Tor for the private test network, then pass --{name} /absolute/path/to/{name}. No software was downloaded.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tor", default=os.environ.get("TOR"))
    parser.add_argument("--tor-gencert", default=os.environ.get("TOR_GENCERT"))
    parser.add_argument("--check", action="store_true", help="verify curl transfers then clean up and exit")
    args = parser.parse_args()
    tor = executable(args.tor, "tor", "tor-*/src/app/tor")
    gencert = executable(args.tor_gencert, "tor-gencert", "tor-*/src/tools/tor-gencert")
    if not shutil.which("curl"):
        raise SystemExit("curl is required for the HTTP self-check")
    root = pathlib.Path(__file__).resolve().parent.parent
    print("Building Veil and its private-network test harness...", flush=True)
    subprocess.run(["go", "build", "-trimpath", "-o", "bin/veil", "./cmd/veil"], cwd=root, check=True)
    subprocess.run(["go", "test", "-c", "-race", "-o", "bin/circuit-test", "./circuit"], cwd=root, check=True)
    command = [sys.executable, str(root / "scripts/check_local_directory.py"), "--tor", tor, "--gencert", gencert, "--veil", "bin/veil", "--proxy-demo", "bin/circuit-test"]
    if args.check:
        command.append("--proxy-check")
    os.chdir(root)
    os.execv(sys.executable, command)


if __name__ == "__main__":
    main()
