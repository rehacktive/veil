#!/usr/bin/env python3
"""Probe an onion HTTP endpoint through an independently operated Tor SOCKS client.

Requires curl 8.4+ (streaming response size limit). Does not start Tor or change
service state. Exit 0 means HTTP 200 with the expected UTF-8 text; 1 means probe
failure, and 2 means invalid arguments. Emits one JSON result without response
contents, credentials or the onion address. Redirects are never followed.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import pathlib
import re
import subprocess
import tempfile
import time
import urllib.parse

MAX_BYTES = 1024 * 1024


def onion_url(value):
    try:
        url = urllib.parse.urlsplit(value)
        host = url.hostname or ""
        if (url.scheme not in ("http", "https") or url.username is not None
                or url.password is not None or url.fragment
                or any(c.isspace() or ord(c) < 32 for c in value)
                or not re.fullmatch(r"[a-z2-7]{56}\.onion", host)
                or (url.port is not None and not 1 <= url.port <= 65535)):
            raise ValueError()
        raw = base64.b32decode(host[:-6].upper())
        checksum = hashlib.sha3_256(b".onion checksum" + raw[:32] + raw[-1:]).digest()[:2]
        if raw[-1] != 3 or raw[32:34] != checksum:
            raise ValueError()
    except ValueError:
        raise argparse.ArgumentTypeError("expected a valid v3 onion HTTP(S) URL without credentials or fragment") from None
    return value


def socks_address(value):
    try:
        parsed = urllib.parse.urlsplit("socks5h://" + value)
        if (parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment
                or parsed.port is None or not 1 <= parsed.port <= 65535
                or not ipaddress.ip_address(parsed.hostname).is_loopback
                or "%" in value or any(c.isspace() for c in value)):
            raise ValueError()
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError("SOCKS endpoint must be numeric loopback IP:port (IPv6 in brackets)") from None
    return value


def probe(url, socks, expected, timeout=180, curl="curl"):
    started = time.monotonic()
    result = {"ok": False, "http_status": None}
    try:
        # -q must be the first option: a user's .curlrc must not introduce
        # redirects, direct connections, or disabled certificate verification.
        version = subprocess.run([curl, "-q", "--version"], capture_output=True, timeout=5, check=True)
        match = re.match(rb"curl (\d+)\.(\d+)\.(\d+)", version.stdout)
        if not match or tuple(map(int, match.groups())) < (8, 4, 0):
            result["error"] = "curl 8.4 or newer is required"
            return result
        with tempfile.TemporaryDirectory(prefix="veil-onion-probe-") as folder:
            body = pathlib.Path(folder) / "body"
            command = [curl, "-q", "--silent", "--show-error",
                       "--proxy", "socks5h://" + socks, "--noproxy", "",
                       "--proto", "=http,https", "--max-time", str(timeout),
                       "--max-filesize", str(MAX_BYTES), "--output", str(body),
                       "--write-out", "%{http_code}", "--url", url]
            completed = subprocess.run(command, capture_output=True, timeout=timeout + 5)
            status = completed.stdout.decode("ascii", errors="replace").strip()
            result["http_status"] = int(status) if re.fullmatch(r"[1-5]\d\d", status) else None
            if completed.returncode:
                result["error"] = "curl transport failure"
                result["curl_exit"] = completed.returncode
            elif status != "200":
                result["error"] = "expected HTTP 200 (redirects are not followed)"
            else:
                with body.open("rb") as response:
                    data = response.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    result["error"] = "response exceeds 1 MiB"
                elif expected.encode("utf-8") not in data:
                    result["error"] = "expected content missing"
                else:
                    result["ok"] = True
    except subprocess.TimeoutExpired:
        result["error"] = "probe timed out"
    except (OSError, subprocess.CalledProcessError):
        result["error"] = "could not execute curl or read probe output"
    finally:
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", type=onion_url)
    parser.add_argument("--socks", required=True, type=socks_address,
                        help="independent C Tor SOCKS endpoint, e.g. 127.0.0.1:9050")
    parser.add_argument("--expect", required=True, help="nonempty UTF-8 text required in the response")
    parser.add_argument("--timeout", type=int, default=180, help="request deadline in seconds (1..600)")
    args = parser.parse_args()
    if not args.expect or not 1 <= args.timeout <= 600:
        parser.error("--expect must be nonempty and --timeout must be in 1..600")
    result = probe(args.url, args.socks, args.expect, args.timeout)
    print(json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
