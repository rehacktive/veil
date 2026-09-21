import json
import struct
import unittest

from traffic_fingerprint import RecordTrace, client_hello, summarize


def vec(data, width):
    return len(data).to_bytes(width, "big") + data


class TrafficFingerprintTests(unittest.TestCase):
    def hello(self):
        sni = b"do-not-store.example"
        sni_body = vec(b"\x00" + vec(sni, 2), 2)
        extensions = struct.pack("!HH", 0, len(sni_body)) + sni_body
        extensions += struct.pack("!HH", 43, 3) + bytes([2, 3, 4])
        return b"\x03\x03" + b"R" * 32 + vec(b"secret-session", 1) + vec(b"\x13\x01", 2) + vec(b"\x00", 1) + vec(extensions, 2)

    def test_fragmented_tcp_and_tls_records(self):
        hello = self.hello()
        handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
        wire = b"".join(struct.pack("!BHH", 22, 0x303, len(part)) + part
                        for part in (handshake[:12], handshake[12:]))
        trace = RecordTrace()
        for byte in wire:
            trace.feed(bytes([byte]))
        self.assertEqual(trace.hello["supported_versions"], [0x304])
        self.assertEqual(trace.hello["cipher_suites"], [0x1301])
        self.assertEqual(len(trace.records), 2)
        report = json.dumps(trace.report())
        for private in ("do-not-store.example", "secret-session", "R" * 32):
            self.assertNotIn(private, report)

    def test_key_share_metadata_without_key_material(self):
        key = b"secret-key-material"
        body = vec(struct.pack("!H", 4588) + vec(key, 2), 2)
        hello = self.hello()
        # Replace the extension list after the fixed test session/suites fields.
        prefix_length = 34 + 1 + len(b"secret-session") + 2 + 2 + 1 + 1
        prefix = hello[:prefix_length]
        parsed = client_hello(prefix + vec(struct.pack("!HH", 51, len(body)) + body, 2))
        self.assertEqual(parsed["key_shares"], [{"group": 4588, "length": len(key)}])
        self.assertNotIn("secret-key-material", json.dumps(parsed))
        for body in (b"", b"\x00\x03abc", b"\x00\x05\x00\x1d\x00\x02x"):
            with self.assertRaises(ValueError):
                client_hello(prefix + vec(struct.pack("!HH", 51, len(body)) + body, 2))
        with self.assertRaises(ValueError):
            client_hello(prefix + vec(b"\x00\x00\x00\x01x", 2))

    def test_truncations_and_bounds(self):
        for length in range(34):
            with self.assertRaises(ValueError):
                client_hello(self.hello()[:length])
        with self.assertRaises(ValueError):
            RecordTrace().feed(struct.pack("!BHH", 22, 0x303, 20000))
        trace = RecordTrace()
        trace.feed(struct.pack("!BHH", 23, 0x303, 1) + b"x")
        self.assertEqual(trace.records[0]["length"], 1)
        self.assertIsNone(trace.hello)
        for _ in range(300):
            trace.feed(struct.pack("!BHH", 23, 0x303, 1) + b"x")
        self.assertEqual(len(trace.records), 256)
        self.assertFalse(trace.buffer)

class RepeatedMeasurementTests(unittest.TestCase):
    def test_stable_fields_are_separate_from_random_lengths(self):
        pairs = []
        for length in (12, 22, 30):
            pair = {}
            for label in ("veil", "c_tor"):
                pair[label] = {"outbound": {"client_hello": {
                    "cipher_suites": [0x1301] if label == "veil" else [0x1303],
                    "server_name_length": length if label == "veil" else 20,
                    "server_name_present": True,
                }, "records": [{"length": 1500 + length}]}}
            pairs.append(pair)
        summary = summarize(pairs)
        self.assertEqual(summary["sample_count"], 3)
        self.assertIn("server_name_length", summary["veil"]["variable_fields"])
        self.assertNotIn("server_name_length", summary["veil"]["stable_fields"])
        self.assertEqual(list(summary["stable_differences"]), ["cipher_suites"])


if __name__ == "__main__":
    unittest.main()
