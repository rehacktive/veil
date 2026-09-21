import json
import struct
import unittest

import test_traffic_fingerprint as fingerprint_tests
from traffic_workload import TLSMetadata, phase_summary


class WorkloadMeasurementTests(unittest.TestCase):
    def test_fragmented_records_keep_only_metadata(self):
        hello = fingerprint_tests.TrafficFingerprintTests().hello()
        handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
        wire = b"".join(struct.pack("!BHH", 22, 0x303, len(part)) + part
                        for part in (handshake[:10], handshake[10:]))
        trace = TLSMetadata(10, True)
        for byte in wire:
            trace.feed(bytes([byte]), now=11)
        self.assertEqual(len(trace.records), 2)
        self.assertEqual(trace.records[0][0], 1000)
        self.assertTrue(trace.hello["server_name_present"])
        encoded = json.dumps({"hello": trace.hello, "records": trace.records})
        for secret in ("do-not-store.example", "secret-session", "RRRR"):
            self.assertNotIn(secret, encoded)
        self.assertFalse(trace.handshake)
        self.assertFalse(trace.buffer)

    def test_record_limits_and_invalid_lengths(self):
        for kind, length in ((23, 20000), (1, 10)):
            with self.assertRaises(ValueError):
                TLSMetadata(0).feed(struct.pack("!BHH", kind, 0x303, length))
        trace = TLSMetadata(0)
        trace.records = [[0, 23, 1]] * 100000
        with self.assertRaises(ValueError):
            trace.feed(struct.pack("!BHH", 23, 0x303, 1) + b"x")

    def test_phase_boundaries_and_guard_filter(self):
        connection = {"role": "guard", "opened_ms": 1,
                      "outbound": {"records": [[0, 23, 4], [10, 23, 6], [20, 23, 8], [30, 23, 2]]},
                      "inbound": {"records": [[15, 23, 100]]}}
        other = dict(connection, role="other_relay")
        got = phase_summary([connection, other], {"start_ms": 10, "end_ms": 30})
        self.assertEqual(got["outbound"]["records"], 2)
        self.assertEqual(got["outbound"]["tls_wire_bytes"], 24)
        self.assertEqual(got["outbound"]["median_record_gap_ms"], 10)
        self.assertEqual(got["inbound"]["tls_wire_bytes"], 105)
        self.assertIsNone(got["inbound"]["median_record_gap_ms"])
        self.assertEqual(got["guard_connections_opened"], 0)


if __name__ == "__main__":
    unittest.main()
