#!/usr/bin/env python3
"""Matched synthetic onion workloads, captured only through loopback TLS taps.

The tap stores TLS metadata, never record bodies, application payloads, names,
keys or cookies. This measures TLS records, NOT packets or Tor cells.
"""
import collections
import contextlib
import gzip
import hashlib
import json
import platform
import pathlib
import socket
import socketserver
import statistics
import struct
import subprocess
import threading
import time

from check_local_tor import free_port
from traffic_fingerprint import client_hello


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError("short local connection")
        data.extend(part)
    return bytes(data)


class TLSMetadata:
    def __init__(self, origin, parse_hello=False):
        self.origin, self.parse_hello = origin, parse_hello
        self.buffer, self.handshake = bytearray(), bytearray()
        self.records, self.hello = [], None

    def feed(self, data, now=None):
        self.buffer.extend(data)
        now = time.monotonic() if now is None else now
        while len(self.buffer) >= 5:
            kind, version, size = struct.unpack("!BHH", self.buffer[:5])
            if kind not in (20, 21, 22, 23) or size > 18432:
                raise ValueError("invalid TLS record in controlled tap")
            if len(self.buffer) < 5 + size:
                break
            if len(self.records) >= 100000:
                raise ValueError("TLS metadata limit exceeded")
            body = self.buffer[5:5 + size]
            del self.buffer[:5 + size]
            self.records.append([round((now - self.origin) * 1000, 3), kind, size])
            if self.parse_hello and self.hello is None and kind == 22:
                self.handshake.extend(body)
                if len(self.handshake) > 65536:
                    raise ValueError("handshake metadata limit exceeded")
                if len(self.handshake) >= 4:
                    length = int.from_bytes(self.handshake[1:4], "big")
                    if self.handshake[0] != 1:
                        raise ValueError("outbound first handshake was not ClientHello")
                    if len(self.handshake) >= length + 4:
                        self.hello = client_hello(bytes(self.handshake[4:4 + length]))
                        self.handshake.clear()


class WorkloadTap:
    def __init__(self, ports, guard):
        self.ports, self.guard = set(ports), guard
        self.origin = time.monotonic()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.connections, self.workers, self.sockets, self.errors = [], [], [], []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(32)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.acceptor = threading.Thread(target=self.accept)
        self.acceptor.start()

    def milliseconds(self):
        return round((time.monotonic() - self.origin) * 1000, 3)

    def accept(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                if len(self.workers) >= 64:
                    conn.close()
                    self.errors.append("connection limit exceeded")
                    continue
                self.sockets.append(conn)
                worker = threading.Thread(target=self.connection, args=(conn,))
                self.workers.append(worker)
            worker.start()

    def connection(self, client):
        relay, record = None, None
        try:
            client.settimeout(10)
            version, count = exact(client, 2)
            methods = exact(client, count)
            if version != 5 or 0 not in methods:
                raise ValueError("unsupported local tap authentication")
            client.sendall(b"\x05\x00")
            if exact(client, 4) != b"\x05\x01\x00\x01":
                raise ValueError("tap permits numeric IPv4 CONNECT only")
            address = socket.inet_ntoa(exact(client, 4))
            port = struct.unpack("!H", exact(client, 2))[0]
            if address != "127.0.0.1" or port not in self.ports:
                raise ValueError("tap target outside explicit private relay allowlist")
            relay = socket.create_connection((address, port), timeout=10)
            with self.lock:
                self.sockets.append(relay)
                record = {"id": len(self.connections) + 1, "role": "guard" if port == self.guard else "other_relay",
                          "opened_ms": self.milliseconds(), "closed_ms": None,
                          "outbound": TLSMetadata(self.origin, True), "inbound": TLSMetadata(self.origin)}
                self.connections.append(record)
            client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            client.settimeout(1)
            relay.settimeout(1)

            def pump(source, target, trace):
                try:
                    while not self.stop.is_set():
                        try:
                            data = source.recv(32768)
                        except socket.timeout:
                            continue
                        if not data:
                            break
                        trace.feed(data)
                        target.sendall(data)
                except ValueError as error:
                    with self.lock:
                        self.errors.append(str(error))
                except OSError:
                    pass
                finally:
                    with contextlib.suppress(OSError):
                        target.shutdown(socket.SHUT_WR)
            backward = threading.Thread(target=pump, args=(relay, client, record["inbound"]))
            backward.start()
            pump(client, relay, record["outbound"])
            backward.join()
        except (OSError, EOFError, ValueError) as error:
            if not self.stop.is_set():
                with self.lock:
                    self.errors.append(str(error))
        finally:
            if record is not None:
                record["closed_ms"] = self.milliseconds()
            client.close()
            if relay:
                relay.close()

    def finish(self, cutoff):
        self.stop.set()
        self.listener.close()
        self.acceptor.join(2)
        with self.lock:
            sockets, workers = list(self.sockets), list(self.workers)
        for sock in sockets:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        for worker in workers:
            worker.join(3)
            if worker.is_alive():
                raise RuntimeError("tap worker did not stop")
        if self.errors:
            raise RuntimeError("invalid measurement: " + "; ".join(self.errors))
        result = []
        for connection in self.connections:
            if connection["opened_ms"] >= cutoff:
                continue
            item = {key: connection[key] for key in ("id", "role", "opened_ms")}
            closed = connection["closed_ms"]
            item["closed_ms"] = closed if closed is not None and closed <= cutoff else None
            item["open_at_observation_end"] = item["closed_ms"] is None
            for direction in ("outbound", "inbound"):
                trace = connection[direction]
                item[direction] = {"client_hello": trace.hello,
                                   "records": [r for r in trace.records if r[0] < cutoff]}
            result.append(item)
        return result


class FixtureHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        request = bytearray()
        while b"\r\n\r\n" not in request:
            request.extend(exact(self.request, 1))
            if len(request) > 8192:
                raise ValueError("fixture request too large")
        path = request.split(b" ", 2)[1]
        if path not in (b"/small", b"/bulk"):
            return
        size = 4096 if path == b"/small" else 2 * 1024 * 1024
        header = f"HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n".encode()
        self.request.sendall(header + b"V" * size)


class FixtureServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@contextlib.contextmanager
def running(command, log_path, environment=None):
    with log_path.open("w") as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=environment)
        try:
            yield proc
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


def wait_ready(proc, log, marker, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("measurement process exited: " + log.read_text()[-2000:])
        if marker in log.read_text():
            return
        time.sleep(0.1)
    raise RuntimeError("measurement startup timed out: " + log.read_text()[-2000:])


def request(socks_port, host, path):
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", socks_port), timeout=60) as sock:
        sock.settimeout(60)
        sock.sendall(b"\x05\x01\x02")
        if exact(sock, 2) != b"\x05\x02":
            raise ValueError("fixture SOCKS authentication unavailable")
        sock.sendall(b"\x01\x08workload\x05scope")
        if exact(sock, 2) != b"\x01\x00":
            raise ValueError("fixture SOCKS authentication rejected")
        name = host.encode()
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + b"\x00\x50")
        version, status, _, kind = exact(sock, 4)
        if version != 5 or status != 0:
            raise ValueError(f"fixture SOCKS CONNECT rejected: {status}")
        size = {1: 4, 4: 16}.get(kind)
        if kind == 3:
            size = exact(sock, 1)[0]
        if size is None:
            raise ValueError("invalid SOCKS address type")
        exact(sock, size + 2)
        wire = f"GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        sock.sendall(wire)
        response = bytearray()
        while part := sock.recv(32768):
            response.extend(part)
            if len(response) > 2 * 1024 * 1024 + 1024:
                raise ValueError("fixture response too large")
        header, payload = bytes(response).split(b"\r\n\r\n", 1)
        expected = 4096 if path == "small" else 2 * 1024 * 1024
        if not header.startswith(b"HTTP/1.1 200 OK") or payload != b"V" * expected:
            raise ValueError("fixture data integrity failure")
    return {"elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            "request_bytes": len(wire), "response_bytes": len(response), "payload_bytes": expected}


def phase_summary(connections, phase):
    result = {"duration_ms": round(phase["end_ms"] - phase["start_ms"], 3)}
    for direction in ("outbound", "inbound"):
        records = [r for c in connections if c["role"] == "guard" for r in c[direction]["records"]
                   if phase["start_ms"] <= r[0] < phase["end_ms"]]
        times = sorted(r[0] for r in records)
        gaps = [round(b - a, 3) for a, b in zip(times, times[1:])]
        histogram = collections.Counter(r[2] for r in records)
        result[direction] = {"records": len(records), "tls_wire_bytes": sum(r[2] + 5 for r in records),
                             "record_payload_lengths": dict(sorted(histogram.items())),
                             "median_record_gap_ms": statistics.median(gaps) if gaps else None,
                             "max_record_gap_ms": max(gaps) if gaps else None}
    result["guard_connections_opened"] = sum(c["role"] == "guard" and phase["start_ms"] <= c["opened_ms"] < phase["end_ms"] for c in connections)
    return result


def run_sample(tor, veil, root, common, ports, guard, config, host, implementation, idle):
    import os
    sample_dir = root / implementation
    sample_dir.mkdir(mode=0o700)
    socks = free_port()
    tap = WorkloadTap(ports, guard)
    phases, requests = {}, {}
    log = sample_dir / "client.log"
    if implementation == "veil":
        environment = dict(os.environ, VEIL_TEST_LOCAL_TAP=f"127.0.0.1:{tap.port}")
        command = [veil, "proxy", "-config", str(config), "-state", str(sample_dir / "state"),
                   "-listen", f"127.0.0.1:{socks}", "-onion-only", "-debug", "-bootstrap-timeout", "180s"]
        marker = "socks5_ready"
    else:
        environment = None
        data = sample_dir / "data"
        data.mkdir(mode=0o700)
        cfg = sample_dir / "torrc"
        cfg.write_text("\n".join(common + [f'DataDirectory "{data}"', f"SocksPort 127.0.0.1:{socks} IsolateSOCKSAuth",
                                         f"Socks5Proxy 127.0.0.1:{tap.port}"]) + "\n")
        command = [tor, "--defaults-torrc", "/dev/null", "-f", str(cfg)]
        marker = "Bootstrapped 100%"
    try:
        with running(command, log, environment) as proc:
            wait_ready(proc, log, marker)
            warm_started = tap.milliseconds()
            retries = 0
            deadline = time.monotonic() + 180
            while True:
                try:
                    request(socks, host, "small")
                    break
                except (OSError, EOFError, ValueError):
                    retries += 1
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(2)
            time.sleep(5)
            phases["preparation"] = {"start_ms": 0, "end_ms": tap.milliseconds(), "warm_request_started_ms": warm_started, "warm_failures": retries}
            for name, paths in [("single", ["small"]), ("burst", ["small"] * 4), ("bulk", ["bulk"]), ("idle", [])]:
                start = tap.milliseconds()
                requests[name] = []
                for index, path in enumerate(paths):
                    if index:
                        time.sleep(0.25)
                    requests[name].append(request(socks, host, path))
                if name == "idle":
                    time.sleep(idle)
                phases[name] = {"start_ms": start, "end_ms": tap.milliseconds()}
            cutoff = tap.milliseconds()
        connections = tap.finish(cutoff)
    except BaseException:
        tap.finish(tap.milliseconds())
        raise
    summaries = {name: phase_summary(connections, phase) for name, phase in phases.items()}
    return {"phases": phases, "requests": requests, "metrics": summaries, "connections": connections,
            "observation_end_ms": cutoff,
            "guard_channels_open_at_end": sum(c["role"] == "guard" and c["open_at_observation_end"] for c in connections)}


def compare_workload(tor, veil, root, authority_line, guard, ports, config, output, samples=3, idle=60):
    if not 1 <= samples <= 10 or not 10 <= idle <= 300:
        raise ValueError("invalid workload bounds")
    output.parent.mkdir(parents=True, exist_ok=True)
    rsa = authority_line.split()[-1]
    common = ["TestingTorNetwork 1", "ClientOnly 1", "DirAllowPrivateAddresses 1", "UseDefaultFallbackDirs 0", "EnforceDistinctSubnets 0",
              "ExtendAllowPrivateAddresses 1", "UseEntryGuards 1", f"EntryNodes ${rsa}", "StrictNodes 1",
              "VanguardsLiteEnabled 1", "Log notice stdout", authority_line]
    server = FixtureServer(("127.0.0.1", 0), FixtureHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    data = root / "workload-host"
    data.mkdir(mode=0o700)
    hidden = root / "workload-onion"
    hidden.mkdir(mode=0o700)
    cfg = root / "workload-host.torrc"
    cfg.write_text("\n".join([line for line in common if not line.startswith(("EntryNodes ", "StrictNodes "))] + [f'DataDirectory "{data}"', "SocksPort 0", f'HiddenServiceDir "{hidden}"',
                                      f"HiddenServicePort 80 127.0.0.1:{server.server_address[1]}"]) + "\n")
    report = {"schema": 1, "scope": "matched synthetic onion workload over controlled loopback TLS taps",
              "tor_build": subprocess.check_output([tor, "--version"], text=True).splitlines(),
              "go_build": subprocess.check_output(["go", "version"], text=True).strip(), "platform": platform.platform(),
              "veil_binary_sha256": hashlib.sha256(pathlib.Path(veil).read_bytes()).hexdigest(),
              "configuration": {"sample_pairs": samples, "idle_seconds": idle, "warmup_settle_seconds": 5,
                                "native_build_tag": "veiltraffic", "race_instrumented": False,
                                "reference_entry_guards": True, "reference_vanguards_lite": True,
                                "private_relays": len(ports), "shared_service": "C Tor onion host",
                                "guard_selection": "sole consensus Guard; reference explicitly pinned to it",
                                "application": "identical SOCKS-auth scope; HTTP Connection: close; exact payload validation"},
              "limitations": ["TLS record metadata, not IP packets, TCP segmentation or decrypted Tor cells.",
                              "Both clients traverse the same local SOCKS observation shim; it can affect buffering and scheduling.",
                              "One machine and five private relays; local latency and CPU costs are not public-network conditions.",
                              "Preparation/bootstrap is reported separately and is not a matched workload metric.",
                              "Application idle includes protocol maintenance; encrypted records cannot be labeled as pure padding.",
                              "Record attribution uses completion time at the tap; records may cross phase boundaries.",
                              "Open-at-end channels are right-censored, not measured full lifetimes.",
                              "Small sample counts cannot establish anonymity or statistical indistinguishability."], "pairs": []}
    server_thread.start()
    try:
        log = root / "workload-host.log"
        with running([tor, "--defaults-torrc", "/dev/null", "-f", str(cfg)], log) as proc:
            wait_ready(proc, log, "Bootstrapped 100%")
            host = (hidden / "hostname").read_text().strip()
            for index in range(samples):
                sample_root = root / f"workload-{index}"
                sample_root.mkdir(mode=0o700)
                order = ["veil", "c_tor"] if index % 2 == 0 else ["c_tor", "veil"]
                pair = {"order": order}
                for implementation in order:
                    print(f"Workload pair {index + 1}/{samples}: {implementation}; idle {idle}s", flush=True)
                    pair[implementation] = run_sample(tor, veil, sample_root, common, ports, guard, config, host, implementation, idle)
                    print(json.dumps({"completed": implementation, "bulk": pair[implementation]["metrics"]["bulk"],
                                      "idle": pair[implementation]["metrics"]["idle"]}), flush=True)
                report["pairs"].append(pair)
                # Save completed pairs incrementally; incomplete attempts never masquerade as successful trials.
                output.write_text(json.dumps(report, indent=2) + "\n")
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join()
    trace_path = output.with_suffix(".traces.json.gz")
    with gzip.open(trace_path, "wt", encoding="utf8") as archive:
        json.dump(report, archive, separators=(",", ":"))
    for pair in report["pairs"]:
        for implementation in ("veil", "c_tor"):
            for connection in pair[implementation]["connections"]:
                for direction in ("outbound", "inbound"):
                    del connection[direction]["records"]
    report["record_trace_archive"] = trace_path.name
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Matched workload report: {output}", flush=True)
