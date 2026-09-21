#!/usr/bin/env python3
"""Exercise native directory bootstrap against a private three-relay Tor network.

Requires existing Tor, tor-gencert, and Veil executables. Creates one local
v3 authority and two non-exit relays, without public authorities/fallbacks or
SOCKS. Only --stream-test enables an exit, limited to its loopback echo port.
All keys, cookies, caches, and processes are temporary.
"""
import argparse
import contextlib
import base64
import json
import os
import pathlib
import selectors
import shlex
import socket
import subprocess
import sys
import tempfile
import time

from check_local_tor import free_port
from local_stream_services import services


def control_descriptor(port, data):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        reader = sock.makefile("rb")
        cookie = (data / "control_auth_cookie").read_bytes().hex()
        sock.sendall(f"AUTHENTICATE {cookie}\r\n".encode())
        assert reader.readline() == b"250 OK\r\n"
        sock.sendall(b"GETINFO status/fresh-relay-descs\r\n")
        lines = []
        while True:
            line = reader.readline()
            if line == b"250 OK\r\n":
                return b"".join(lines)
            if not line or (line[:1] == b"5" and line[1:3].isdigit() and line[3:4] in (b" ", b"-")):
                raise RuntimeError(f"control query failed: {line!r}")
            lines.append(line)


def check_watch(veil, config, state, processes):
    guard_path = state / "guard.json"
    initial = json.loads(guard_path.read_text())
    sample = [entry["RSA"] for entry in initial["Sample"]]
    if not sample:
        raise RuntimeError("test network has no weighted stable directory guards")
    command = [veil, "directory-watch", "-config", str(config), "-state", str(state), "-timeout", "90s"]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    processes.append(proc)
    versions = set()
    deadline = time.monotonic() + 90
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline and len(versions) < 2:
                events = selector.select(timeout=1)
                if not events:
                    if proc.poll() is not None:
                        raise RuntimeError("directory-watch exited: " + proc.stderr.read())
                    continue
                line = proc.stdout.readline()
                if not line:
                    raise RuntimeError("directory-watch closed output: " + proc.stderr.read())
                status = json.loads(line)
                if status["live"]:
                    versions.add(status["directory"]["valid_after"])
            if len(versions) < 2:
                raise RuntimeError("no scheduled consensus refresh observed")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    refreshed = json.loads(guard_path.read_text())
    assert [entry["RSA"] for entry in refreshed["Sample"]] == sample, "refresh replaced guard sample"
    assert any(entry["ConfirmedOrder"] for entry in refreshed["Sample"]), "directory guard was not confirmed"
    restarted = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    processes.append(restarted)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(restarted.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=5):
                raise RuntimeError("cached directory was not restored promptly")
            line = restarted.stdout.readline()
            if not line:
                raise RuntimeError("warm restart failed: " + restarted.stderr.read())
            status = json.loads(line)
            assert status["live"] and status["directory"]["valid_after"] in versions
            assert json.loads(guard_path.read_text()) == refreshed, "restart changed guard state"
    finally:
        restarted.terminate()
        restarted.wait(timeout=5)
    return {"scheduled_refresh": True, "consensuses_seen": len(versions), "guard_sample_preserved": True, "guard_confirmed": True, "warm_restart": True}


def proxy_demo(binary, environment, processes, check):
    environment["VEIL_TEST_PROXY_DEMO"] = "1"
    child = subprocess.Popen([binary, "-test.run", "^TestLocalTorProxyDemo$", "-test.v", "-test.timeout", "0"], env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    processes.append(child)
    ready = None
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 30
        pending = b""
        while time.monotonic() < deadline:
            if not selector.select(timeout=1):
                if child.poll() is not None:
                    raise RuntimeError("proxy harness exited before ready")
                continue
            chunk = os.read(child.stdout.fileno(), 65536)
            if not chunk:
                raise RuntimeError("proxy harness closed output before ready")
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                if line.startswith(b"{"):
                    ready = json.loads(line)
                    break
            if ready:
                break
        if not ready or ready.get("event") != "proxy_demo_ready":
            raise RuntimeError("proxy startup timed out")
    command = ["curl", "--fail", "--silent", "--show-error", "--max-time", "30", "--noproxy", "", "--socks5-hostname", ready["listen"], ready["url"]]
    result = subprocess.run(command, capture_output=True, text=True, timeout=35, check=True)
    if "Veil SOCKS5 works" not in result.stdout:
        raise RuntimeError("unexpected demo HTTP response")
    large = subprocess.run(command[:-1] + ["--proxy-user", "demo:isolation", ready["url"] + "large"], capture_output=True, timeout=35, check=True)
    if large.stdout != b"V" * (2 * 1024 * 1024):
        raise RuntimeError("SOCKS download failed data-integrity check")
    print(result.stdout.strip(), flush=True)
    print("Verified: hostname resolution at the exit, SOCKS5 tokens, and a 2 MiB download.", flush=True)
    print("\nTry this in another terminal:\n" + shlex.join(command), flush=True)
    print("Private local test only: the exit permits this fixture's port, not the public internet.", flush=True)
    if check:
        child.terminate()
        child.wait(timeout=5)
        if child.returncode != 0:
            raise RuntimeError(child.stdout.read())
        return
    print("Press Ctrl-C here to stop and remove all temporary processes, keys, and configuration.", flush=True)
    while child.poll() is None:
        if any(p.poll() is not None for p in processes[:-1]):
            raise RuntimeError("Tor process exited during SOCKS demo")
        time.sleep(0.2)
    if child.returncode != 0:
        raise RuntimeError(child.stdout.read())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tor", required=True, type=pathlib.Path)
    parser.add_argument("--gencert", required=True, type=pathlib.Path)
    parser.add_argument("--veil", default=pathlib.Path("bin/veil"), type=pathlib.Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--service-test", type=pathlib.Path, help="run native onion hosting tests with a private C Tor SOCKS client")
    mode.add_argument("--watch", action="store_true", help="also verify scheduled refresh and warm restart")
    mode.add_argument("--demo", action="store_true", help="run directory-watch interactively until Ctrl-C, with generated temporary configuration")
    mode.add_argument("--circuit-test", type=pathlib.Path, help="run a compiled Go circuit test binary against three explicit local test hops")
    mode.add_argument("--stream-test", type=pathlib.Path, help="run native TCP stream tests with a loopback-only exit and private DNS fixture")
    mode.add_argument("--proxy-demo", type=pathlib.Path, help="run the native SOCKS5 test harness and curl against a private HTTP fixture")
    parser.add_argument("--proxy-check", action="store_true", help="exit after the proxy demo self-check")
    args = parser.parse_args()
    if args.proxy_check and not args.proxy_demo:
        parser.error("--proxy-check requires --proxy-demo")
    tor, gencert, veil = (str(p.resolve(strict=True)) for p in (args.tor, args.gencert, args.veil))
    test_path = args.service_test or args.proxy_demo or args.stream_test or args.circuit_test
    application_test = bool(args.stream_test or args.proxy_demo)
    circuit_test = str(test_path.resolve(strict=True)) if test_path else None
    processes, logs = [], []
    with contextlib.ExitStack() as stack, tempfile.TemporaryDirectory(prefix="veil-directory-") as temporary:
        echo_port, dns_port, dns_queries = stack.enter_context(services()) if application_test else (0, 53, set())
        root = pathlib.Path(temporary)
        try:
            data = root / "authority"
            keys = data / "keys"
            keys.mkdir(parents=True, mode=0o700)
            data.chmod(0o700)
            authority_or, authority_dir, control = free_port(), free_port(), free_port()
            subprocess.run([gencert, "--create-identity-key", "-i", str(keys / "authority_identity_key"), "-s", str(keys / "authority_signing_key"), "-c", str(keys / "authority_certificate"), "--passphrase-fd", "0"], input="\n", text=True, capture_output=True, check=True, timeout=30)
            certificate = (keys / "authority_certificate").read_text()
            auth_id = next(line.split()[1] for line in certificate.splitlines() if line.startswith("fingerprint "))
            resolver = root / "resolv.conf"
            resolver.write_text(f"nameserver 127.0.0.1:{dns_port}\n")
            common = ["Address 127.0.0.1", "SocksPort 0", "ExitRelay 0", "ExitPolicy reject *:*", "TestingTorNetwork 1", "AssumeReachable 1", "UseDefaultFallbackDirs 0", "DirAllowPrivateAddresses 1", "ServerDNSDetectHijacking 0", f'ServerDNSResolvConfFile "{resolver}"', "Log notice stdout", "ContactInfo local-test@example.invalid"]
            if circuit_test:
                common.append("ExtendAllowPrivateAddresses 1")
            authority = [f'DataDirectory "{data}"', "Nickname GoAuthority", f"ORPort 127.0.0.1:{authority_or}", f"DirPort 127.0.0.1:{authority_dir}", f"ControlPort 127.0.0.1:{control}", "CookieAuthentication 1", "AuthoritativeDirectory 1", "V3AuthoritativeDirectory 1", "V3AuthVotingInterval 20 seconds", "V3AuthVoteDelay 4 seconds", "V3AuthDistDelay 4 seconds", "TestingV3AuthInitialVotingInterval 20 seconds", "TestingV3AuthInitialVoteDelay 4 seconds", "TestingV3AuthInitialDistDelay 4 seconds", "TestingDirAuthVoteGuard *", "TestingAuthDirTimeToLearnReachability 0", "AuthDirMaxServersPerAddr 0"]
            if args.service_test:
                # Match C Tor's testing-network onion period (24 voting rounds)
                # to Veil's consensus-driven minimum of 30 minutes.
                authority = [line.replace("20 seconds", "75 seconds") for line in authority]
                authority.append("ConsensusParams hsdir_interval=30")
                bandwidth_file = root / "bandwidths"
                bandwidth_file.write_text(str(int(time.time())) + "\n")
                authority.append(f'V3BandwidthsFile "{bandwidth_file}"')
            if application_test:
                authority += ["ExitRelay 1", "ExitPolicyRejectPrivate 0", "ExitPolicyRejectLocalInterfaces 0", f"ExitPolicy accept 127.0.0.1:{echo_port},reject *:*"]
            authority_common = [line for line in common if not line.startswith(("ExitRelay ", "ExitPolicy "))] if application_test else common
            config = root / "authority.torrc"
            placeholder = "B" * 40
            authority_line = f"DirAuthority local orport={authority_or} v3ident={auth_id} 127.0.0.1:{authority_dir} {placeholder}"
            config.write_text("\n".join(authority_common + authority + [authority_line]) + "\n")
            setup = subprocess.run([tor, "--defaults-torrc", "/dev/null", "-f", str(config), "--list-fingerprint"], text=True, capture_output=True, timeout=15)
            if setup.returncode:
                raise RuntimeError(setup.stdout + setup.stderr)
            rsa_pin = (data / "fingerprint").read_text().split()[1]
            authority_line = authority_line.replace(placeholder, rsa_pin)
            config.write_text("\n".join(authority_common + authority + [authority_line]) + "\n")
            configs = [config]
            peers = [(data, authority_or, control)]
            for i in range(4 if args.service_test else 2):
                relay_data = root / f"relay{i}"
                relay_data.mkdir(mode=0o700)
                cfg = root / f"relay{i}.torrc"
                relay_or, relay_control = free_port(), free_port() if circuit_test else 0
                cfg.write_text("\n".join(common + [f'DataDirectory "{relay_data}"', f"Nickname GoRelay{i}", f"ORPort 127.0.0.1:{relay_or}", "DirPort 0", f"ControlPort {relay_control}", "CookieAuthentication 1", authority_line]) + "\n")
                peers.append((relay_data, relay_or, relay_control))
                configs.append(cfg)
            service_socks = free_port()
            if args.service_test:
                for cfg in configs:
                    with cfg.open("a") as f:
                        f.write("\nTestingDirAuthVoteHSDir *\n")
                client_data = root / "tor-client"
                client_data.mkdir(mode=0o700)
                cfg = root / "client.torrc"
                cfg.write_text("\n".join([line for line in common if not line.startswith("SocksPort ")] + [f'DataDirectory "{client_data}"', "ClientOnly 1", "EnforceDistinctSubnets 0", "UseEntryGuards 0", "VanguardsLiteEnabled 0", f"SocksPort 127.0.0.1:{service_socks}", authority_line]) + "\n")
                service_client_config = cfg
            for cfg in configs:
                log_path = cfg.with_suffix(".log")
                log = log_path.open("w")
                logs.append((log, log_path))
                processes.append(subprocess.Popen([tor, "--defaults-torrc", "/dev/null", "-f", str(cfg)], stdout=log, stderr=subprocess.STDOUT))
            deadline = time.monotonic() + (240 if args.service_test else 150)
            bootstrap_config = root / "bootstrap.json"
            if args.demo or args.proxy_demo:
                print("Starting a private localhost Tor network; bootstrap can take up to 150 seconds...", file=sys.stderr, flush=True)
            last_error = ""
            while time.monotonic() < deadline:
                if args.service_test and all((peer_data / "fingerprint").exists() for peer_data, _, _ in peers):
                    bandwidth_file.write_text(str(int(time.time())) + "\n" + "".join("node_id=$" + (peer_data / "fingerprint").read_text().split()[1] + " bw=1000\n" for peer_data, _, _ in peers))
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError("Tor process exited")
                try:
                    descriptor = control_descriptor(control, data)
                    ntor_line = next(line.split()[1] for line in descriptor.splitlines() if line.startswith(b"ntor-onion-key "))
                    ntor = base64.b64decode(ntor_line + b"=").hex()
                    ed = (keys / "ed25519_master_id_public_key").read_bytes()[32:].hex()
                    bootstrap_config.write_text(json.dumps({"authorities": [auth_id], "relay": {"address": f"127.0.0.1:{authority_or}", "rsa": rsa_pin, "ed25519": ed, "ntor": ntor}}))
                    result = subprocess.run([veil, "directory-bootstrap", "-config", str(bootstrap_config), "-state", str(root / "client-state"), "-timeout", "10s"], text=True, capture_output=True, timeout=12)
                    if result.returncode == 0:
                        metadata = json.loads(result.stdout)
                        if metadata["relays"] >= (5 if args.service_test else 3):
                            assert metadata["authority_signatures"] == 1
                            cache = root / "client-state" / "directory.json"
                            assert cache.stat().st_mode & 0o777 == 0o600
                            if args.demo:
                                break
                            lifecycle = {}
                            if circuit_test:
                                pins = []
                                # End at the authority; stream mode enables only the
                                # fixture echo port on 127.0.0.1 as an exit destination.
                                for peer_data, peer_or, peer_control in peers[1:] + peers[:1]:
                                    desc = control_descriptor(peer_control, peer_data)
                                    onion = next(line.split()[1] for line in desc.splitlines() if line.startswith(b"ntor-onion-key "))
                                    pins.append({"Address": f"127.0.0.1:{peer_or}", "RSA": (peer_data / "fingerprint").read_text().split()[1], "Ed25519": (peer_data / "keys/ed25519_master_id_public_key").read_bytes()[32:].hex(), "NTor": base64.b64decode(onion + b"=").hex()})
                                environment = dict(os.environ, VEIL_TEST_CIRCUIT_PEERS=json.dumps(pins), VEIL_TEST_STREAM_PORT=str(echo_port))
                                if args.service_test:
                                    client_log_path = service_client_config.with_suffix(".log")
                                    client_log = client_log_path.open("w")
                                    logs.append((client_log, client_log_path))
                                    processes.append(subprocess.Popen([tor, "--defaults-torrc", "/dev/null", "-f", str(service_client_config)], stdout=client_log, stderr=subprocess.STDOUT))
                                    environment.update(VEIL_TEST_HOST_CONFIG=str(bootstrap_config), VEIL_TEST_HOST_STATE=str(root / "client-state"), VEIL_TEST_HOST_SOCKS=f"127.0.0.1:{service_socks}")
                                    subprocess.run([circuit_test, "-test.run", "^TestLocalTorHosting$", "-test.v", "-test.timeout", "7m"], env=environment, check=True, timeout=425)
                                    return
                                if args.proxy_demo:
                                    proxy_demo(circuit_test, environment, processes, args.proxy_check)
                                    assert b"veil.test" in dns_queries, "exit did not perform the DNS lookup"
                                    return
                                subprocess.run([circuit_test, "-test.run", "^TestLocalTorStreams$" if args.stream_test else "^TestLocalTorThreeHop$", "-test.v", "-test.timeout", "90s"], env=environment, check=True, timeout=95)
                                lifecycle["native_three_hop_circuit"] = True
                                if args.stream_test:
                                    assert {b"veil.test", b"missing.test", b"stall.test"}.issubset(dns_queries), dns_queries
                                    lifecycle["native_streams_and_exit_dns"] = True
                            if args.watch:
                                lifecycle = check_watch(veil, bootstrap_config, root / "client-state", processes)
                            print(json.dumps({"lifecycle": lifecycle, "native_directory_bootstrap": True, "tor_version": subprocess.check_output([tor, "--version"], text=True).splitlines()[0], "directory": metadata, "private_cache": True}, indent=2))
                            return
                    last_error = result.stderr or result.stdout
                except (ConnectionError, FileNotFoundError, StopIteration, RuntimeError) as error:
                    last_error = str(error)
                time.sleep(1)
            else:
                raise RuntimeError("directory bootstrap timeout: " + last_error)
            # Keep the peers and their generated keys alive for the watcher's lifetime.
            command = [veil, "directory-watch", "-config", str(bootstrap_config), "-state", str(root / "client-state")]
            print("Running: " + shlex.join(command), file=sys.stderr, flush=True)
            print("Press Ctrl-C to stop. Temporary configuration, keys, and state will be removed.", file=sys.stderr, flush=True)
            watcher = subprocess.Popen(command)
            processes.append(watcher)
            while watcher.poll() is None:
                if any(p.poll() is not None for p in processes[:-1]):
                    raise RuntimeError("Tor process exited during demo")
                time.sleep(0.2)
            if watcher.returncode:
                raise RuntimeError(f"directory-watch exited with status {watcher.returncode}")
        except KeyboardInterrupt:
            if not (args.demo or args.proxy_demo):
                raise
            print("\nStopping local demo.", file=sys.stderr, flush=True)
        except Exception:
            for _, path in logs:
                print(f"\n{path.name}:\n{path.read_text()[-10000:]}")
            raise
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            for log, _ in logs:
                log.close()


if __name__ == "__main__":
    main()
