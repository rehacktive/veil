#!/usr/bin/env python3
"""Check the compiled Go channel client against a temporary localhost C Tor relay.

Requires Python 3 and an existing Tor executable; downloads/installs nothing.
The relay uses a private data directory, no SOCKS or exit service, no descriptor
publishing, no default authorities/fallbacks, and a dummy localhost authority.
Both processes are stopped and temporary relay keys removed on exit.
"""

import argparse
import base64
import json
import pathlib
import socket
import subprocess
import tempfile
import time


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tor", required=True, type=pathlib.Path)
    parser.add_argument("--veil", default=pathlib.Path("bin/veil"), type=pathlib.Path)
    parser.add_argument("--directory-probe", type=pathlib.Path, help="optional compiled scripts/directory_probe.go helper")
    parser.add_argument("--traffic-report", type=pathlib.Path, help="write a controlled TLS fingerprint comparison with C Tor")
    parser.add_argument("--traffic-samples", type=int, default=5, choices=range(1, 21), metavar="1..20", help="independent TLS connections per client (default 5)")
    args = parser.parse_args()
    tor, veil = args.tor.resolve(strict=True), args.veil.resolve(strict=True)
    version = subprocess.check_output([str(tor), "--version"], text=True).splitlines()[0]

    with tempfile.TemporaryDirectory(prefix="veil-tor-") as directory:
        root = pathlib.Path(directory)
        data = root / "data"
        data.mkdir(mode=0o700)
        resolver = root / "resolv.conf"
        resolver.write_text("nameserver 127.0.0.1\n")
        port = free_port()
        control_port = free_port() if args.directory_probe else 0
        config = root / "torrc"
        config.write_text("\n".join([
            f'DataDirectory "{data}"',
            "Nickname VeilInterop",
            "Address 127.0.0.1",
            f"ORPort 127.0.0.1:{port}",
            "SocksPort 0",
            f"ControlPort {control_port}",
            "CookieAuthentication 1",
            "DirPort 0",
            "ExitRelay 0",
            "ExitPolicy reject *:*",
            "PublishServerDescriptor 0",
            "TestingTorNetwork 1",
            "AssumeReachable 1",
            "UseDefaultFallbackDirs 0",
            "FetchServerDescriptors 0",
            "DirAuthority local orport=1 v3ident=" + "A" * 40 + " 127.0.0.1:1 " + "B" * 40,
            "ServerDNSDetectHijacking 0",
            f'ServerDNSResolvConfFile "{resolver}"',
            "Log notice stdout",
        ]) + "\n")
        log_path = root / "tor.log"
        with log_path.open("w") as log:
            proc = subprocess.Popen([str(tor), "--defaults-torrc", "/dev/null", "-f", str(config)], stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 20
                while True:
                    if proc.poll() is not None:
                        raise RuntimeError("Tor exited during startup:\n" + log_path.read_text())
                    rsa_file = data / "fingerprint"
                    ed_file = data / "keys" / "ed25519_master_id_public_key"
                    if rsa_file.exists() and ed_file.exists():
                        public = ed_file.read_bytes()
                        if len(public) == 64 and public.startswith(b"== ed25519v1-public"):
                            break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Tor keys not ready:\n" + log_path.read_text())
                    time.sleep(0.05)

                rsa_pin = rsa_file.read_text().split()[1]
                ed_pin = public[32:].hex()
                command = [str(veil), "channel-check", "-address", f"127.0.0.1:{port}", "-rsa", rsa_pin, "-ed25519", ed_pin, "-timeout", "3s"]
                # Key creation precedes final listener/TLS initialization.
                while True:
                    result = subprocess.run(command, text=True, capture_output=True, timeout=5)
                    if result.returncode == 0:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Go handshake failed:\n" + result.stderr + "\n" + log_path.read_text())
                    time.sleep(0.1)
                metadata = json.loads(result.stdout)
                assert metadata["rsa_identity"] == rsa_pin.lower()
                assert metadata["ed25519_identity"] == ed_pin
                assert metadata["link_protocol"] == 5
                for flag in ("-rsa", "-ed25519"):
                    bad = command.copy()
                    index = bad.index(flag) + 1
                    bad[index] = ("1" if bad[index][0] == "0" else "0") + bad[index][1:]
                    rejected = subprocess.run(bad, text=True, capture_output=True, timeout=5)
                    assert rejected.returncode != 0, f"accepted wrong {flag} pin"
                    assert "invalid Tor certificate chain" in rejected.stderr, rejected.stderr
                result_info = {"tor_version": version, "channel": metadata, "wrong_rsa_rejected": True, "wrong_ed25519_rejected": True}
                if args.directory_probe:
                    # Read public descriptor data through a cookie-authenticated,
                    # localhost-only control connection. Never read onion secrets.
                    with socket.create_connection(("127.0.0.1", control_port), timeout=5) as control:
                        reader = control.makefile("rb")
                        cookie = (data / "control_auth_cookie").read_bytes().hex()
                        control.sendall(f"AUTHENTICATE {cookie}\r\n".encode())
                        assert reader.readline() == b"250 OK\r\n"
                        control.sendall(b"GETINFO status/fresh-relay-descs\r\n")
                        descriptor = []
                        while True:
                            line = reader.readline()
                            if line == b"250 OK\r\n":
                                break
                            if not line or (line[:1] == b"5" and line[1:3].isdigit() and line[3:4] in (b" ", b"-")):
                                raise RuntimeError(f"could not obtain public descriptor: {line!r}")
                            descriptor.append(line)
                        ntor_line = next(line for line in descriptor if line.startswith(b"ntor-onion-key "))
                        ntor_key = base64.b64decode(ntor_line.split()[1] + b"=")
                    source = {"Target": {"Address": f"127.0.0.1:{port}", "Identity": {"RSA": list(bytes.fromhex(rsa_pin)), "Ed25519": list(bytes.fromhex(ed_pin))}}, "OnionKey": list(ntor_key)}
                    while True:
                        probe = subprocess.run([str(args.directory_probe.resolve(strict=True))], input=json.dumps(source), text=True, capture_output=True, timeout=15)
                        if probe.returncode == 0:
                            break
                        if "HTTP status 404" not in probe.stderr or time.monotonic() >= deadline:
                            raise RuntimeError("directory probe failed:\n" + probe.stderr + "\n" + log_path.read_text())
                        # Tor's periodic descriptor generation follows listener setup.
                        time.sleep(0.2)
                    result_info["directory"] = json.loads(probe.stdout)
                if args.traffic_report:
                    from traffic_fingerprint import compare
                    result_info["traffic_fingerprint"] = compare(tor, veil, root, port, rsa_pin, ed_pin, args.traffic_report.resolve(), args.traffic_samples)
                print(json.dumps(result_info, indent=2))
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=3)


if __name__ == "__main__":
    main()
