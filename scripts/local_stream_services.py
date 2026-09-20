"""Loopback-only echo and DNS fixtures for the opt-in C Tor stream check."""
import contextlib
import socketserver
import struct
import threading


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        try:
            mode = self.request.recv(1)
            if mode == b"G":
                request = mode
                while b"\r\n\r\n" not in request and len(request) < 8192:
                    chunk = self.request.recv(1024)
                    if not chunk:
                        return
                    request += chunk
                if b"\r\n\r\n" not in request:
                    return
                body = b"V" * (2 * 1024 * 1024) if request.startswith(b"GET /large ") else b"Veil SOCKS5 works: this HTTP response crossed three native Go Tor hops.\n"
                header = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                self.request.sendall(header + body)
                return
            if mode == b"F":
                self.request.sendall(b"tail")
                return
            if mode != b"E":
                return
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                self.request.sendall(data)
        except (OSError, TimeoutError):
            return


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        if len(packet) < 17 or packet[4:6] != b"\0\1":
            return
        offset, labels = 12, []
        while offset < len(packet):
            size = packet[offset]
            offset += 1
            if not size:
                break
            if size > 63 or offset + size > len(packet):
                return
            labels.append(packet[offset:offset + size].lower())
            offset += size
        if offset + 4 != len(packet):
            return
        name = b".".join(labels)
        self.server.queries.add(name)
        if name == b"stall.test":
            return  # force a cancellable pending BEGIN
        question = packet[12:]
        kind, family = struct.unpack("!HH", packet[offset:])
        ok = name == b"veil.test"
        answer = b""
        if ok and kind == 1 and family == 1:
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x7f\0\0\1"
        header = packet[:2] + struct.pack("!HHHHH", 0x8180 if ok else 0x8183, 1, bool(answer), 0, 0)
        sock.sendto(header + question + answer, self.client_address)


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


@contextlib.contextmanager
def services():
    with EchoServer(("127.0.0.1", 0), Echo) as echo, socketserver.UDPServer(("127.0.0.1", 0), DNS) as dns:
        dns.queries = set()
        threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (echo, dns)]
        for thread in threads:
            thread.start()
        try:
            yield echo.server_address[1], dns.server_address[1], dns.queries
        finally:
            echo.shutdown()
            dns.shutdown()
            for thread in threads:
                thread.join()
