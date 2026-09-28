"""Exercise the probe with real curl and a local SOCKS peer, without public traffic."""
import argparse
import base64
import contextlib
import hashlib
import os
import pathlib
import shutil
import socketserver
import tempfile
import threading
import unittest
from unittest import mock

from onion_probe import MAX_BYTES, onion_url, probe, socks_address

KEY = bytes(range(32))
ADDRESS = base64.b32encode(KEY + hashlib.sha3_256(b".onion checksum" + KEY + b"\x03").digest()[:2] + b"\x03").decode().lower() + ".onion"
URL = "http://" + ADDRESS + "/healthz"


@contextlib.contextmanager
def socks_peer(status=200, body=b"veil-test-ok", location=None, chunked=False):
    requests = []
    errors = []

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            try:
                version, count = self.rfile.read(2)
                assert version == 5 and 0 in self.rfile.read(count)
                self.wfile.write(b"\x05\x00")
                # ATYP 3 proves the onion name reaches SOCKS without local DNS.
                assert self.rfile.read(4) == b"\x05\x01\x00\x03"
                size = self.rfile.read(1)[0]
                host = self.rfile.read(size).decode()
                port = int.from_bytes(self.rfile.read(2), "big")
                self.wfile.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
                headers = []
                while True:
                    line = self.rfile.readline(8192)
                    if line in (b"\r\n", b""):
                        break
                    headers.append(line)
                requests.append((host, port, b"".join(headers)))
                response = f"HTTP/1.1 {status} Test\r\nConnection: close\r\n"
                response += "Transfer-Encoding: chunked\r\n" if chunked else f"Content-Length: {len(body)}\r\n"
                if location:
                    response += f"Location: {location}\r\n"
                self.wfile.write(response.encode() + b"\r\n")
                if chunked:
                    self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
                else:
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Expected when curl rejects an oversized response.
            except Exception as exc:
                errors.append(exc)

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        worker.start()
        try:
            yield f"127.0.0.1:{server.server_address[1]}", requests
        finally:
            server.shutdown()
            worker.join(timeout=6)
    if errors:
        raise AssertionError(errors)


class ProbeValidationTests(unittest.TestCase):
    def test_url_validation(self):
        self.assertEqual(onion_url(URL), URL)
        for value in ("https://example.com/", "file:///etc/passwd", "http://user@" + ADDRESS,
                      "http://" + "a" * 56 + ".onion/", URL + "#fragment", URL + "\n",
                      "http://sub." + ADDRESS, "http://" + ADDRESS + ":0/"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                onion_url(value)

    def test_socks_validation(self):
        for value in ("127.0.0.1:9050", "[::1]:9150"):
            self.assertEqual(socks_address(value), value)
        for value in ("localhost:9050", "192.0.2.1:9050", "127.0.0.1:0", "user@127.0.0.1:9050", "127.0.0.1:9050/path"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                socks_address(value)

    def test_missing_curl_and_timeout(self):
        import subprocess
        for error in (FileNotFoundError(), subprocess.TimeoutExpired("curl", 1)):
            with mock.patch("onion_probe.subprocess.run", side_effect=error):
                result = probe(URL, "127.0.0.1:9050", "ok")
                self.assertFalse(result["ok"])
                self.assertIn("elapsed_seconds", result)

    def test_old_curl_rejected(self):
        import subprocess
        with mock.patch("onion_probe.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"curl 8.3.0")) as run:
            self.assertFalse(probe(URL, "127.0.0.1:9050", "ok")["ok"])
            self.assertEqual(run.call_count, 1)


@unittest.skipUnless(shutil.which("curl"), "requires curl 8.4+")
class ProbeTransportTests(unittest.TestCase):
    def test_success_ignores_proxy_environment_and_curlrc(self):
        with tempfile.TemporaryDirectory() as folder, socks_peer() as (socks, requests):
            pathlib.Path(folder, ".curlrc").write_text('header = "X-Unwanted: curlrc"\nlocation\n')
            with mock.patch.dict(os.environ, {"CURL_HOME": folder, "NO_PROXY": "*", "ALL_PROXY": "http://127.0.0.1:1", "http_proxy": "http://127.0.0.1:1"}):
                result = probe(URL, socks, "veil-test-ok", timeout=3)
            self.assertTrue(result["ok"], result)
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0][:2], (ADDRESS, 80))
            self.assertIn(b"GET /healthz HTTP/1.1", requests[0][2])
            self.assertNotIn(b"X-Unwanted", requests[0][2])

    def test_wrong_content_and_server_error(self):
        for status, body in ((200, b"wrong site"), (503, b"veil-test-ok")):
            with self.subTest(status=status), socks_peer(status, body) as (socks, _):
                result = probe(URL, socks, "veil-test-ok", timeout=3)
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["http_status"], status)

    def test_redirect_is_failure_without_followup(self):
        with socks_peer(302, location="http://example.com/") as (socks, requests):
            result = probe(URL, socks, "veil-test-ok", timeout=3)
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["http_status"], 302)
            self.assertEqual(len(requests), 1)

    def test_body_limit_including_chunked(self):
        for chunked in (False, True):
            with self.subTest(chunked=chunked), socks_peer(body=b"x" * (MAX_BYTES + 1), chunked=chunked) as (socks, _):
                result = probe(URL, socks, "x", timeout=3)
                self.assertFalse(result["ok"], result)
                self.assertEqual(result.get("curl_exit"), 63)


if __name__ == "__main__":
    unittest.main()
