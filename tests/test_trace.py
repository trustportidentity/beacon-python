"""Unit tests for TrustPort Beacon Python SDK."""

import re
import unittest

from trustportidentity_beacon import (
    _ActiveTrace,
    beacon_span,
    current_trace,
    generate_span_id,
    generate_trace_id,
    inject_traceparent,
    parse_traceparent,
    sanitize_headers,
)


class TestW3CTracingAndPII(unittest.TestCase):
    def test_parse_traceparent_valid(self):
        header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        res = parse_traceparent(header)
        self.assertIsNotNone(res)
        trace_id, parent_id, sampled = res
        self.assertEqual(trace_id, "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(parent_id, "00f067aa0ba902b7")
        self.assertTrue(sampled)

    def test_parse_traceparent_invalid(self):
        self.assertIsNone(parse_traceparent(None))
        self.assertIsNone(parse_traceparent(""))
        self.assertIsNone(parse_traceparent("invalid-traceparent"))
        self.assertIsNone(parse_traceparent("00-00000000000000000000000000000000-0000000000000000-00"))

    def test_active_trace_with_w3c_parent(self):
        incoming = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        trace = _ActiveTrace(incoming)
        self.assertEqual(trace.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(trace.parent_span_id, "00f067aa0ba902b7")
        self.assertTrue(re.match(r"^[0-9a-f]{16}$", trace.span_id))
        self.assertEqual(
            trace.traceparent,
            f"00-4bf92f3577b34da6a3ce929d0e0e4736-{trace.span_id}-01",
        )

    def test_active_trace_fresh_generation(self):
        trace = _ActiveTrace()
        self.assertTrue(re.match(r"^[0-9a-f]{32}$", trace.trace_id))
        self.assertTrue(re.match(r"^[0-9a-f]{16}$", trace.span_id))
        self.assertIsNone(trace.parent_span_id)

    def test_span_hierarchy(self):
        trace = _ActiveTrace()
        span = trace.start_span("db_query", "database", {"query": "SELECT 1"})
        span.set_tag("db.system", "postgresql")
        span.end()

        self.assertEqual(len(trace.spans), 1)
        rec = trace.spans[0]
        self.assertEqual(rec["name"], "db_query")
        self.assertEqual(rec["type"], "database")
        self.assertTrue(re.match(r"^[0-9a-f]{16}$", rec["span_id"]))
        self.assertEqual(rec["parent_span_id"], trace.span_id)
        self.assertEqual(rec["tags"]["db.system"], "postgresql")

    def test_sanitize_headers(self):
        raw = {
            "Authorization": "Bearer secret-token-123",
            "Cookie": "sessionid=secret_cookie_val",
            "X-Api-Key": "key-secret-999",
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json",
        }
        sanitized = sanitize_headers(raw)
        self.assertEqual(sanitized["Authorization"], "[Filtered]")
        self.assertEqual(sanitized["Cookie"], "[Filtered]")
        self.assertEqual(sanitized["X-Api-Key"], "[Filtered]")
        self.assertEqual(sanitized["User-Agent"], "Mozilla/5.0")
        self.assertEqual(sanitized["Accept"], "application/json")

    def test_inject_traceparent(self):
        trace = _ActiveTrace()
        headers = {}
        inject_traceparent(headers, trace)
        self.assertEqual(headers["traceparent"], trace.traceparent)

    def test_breadcrumbs(self):
        trace = _ActiveTrace()
        trace.add_breadcrumb("log", "User added item to cart", "info")
        trace.add_breadcrumb("query", "SELECT * FROM inventory WHERE item_id = 42", "info", {"duration_ms": 1.2})
        self.assertEqual(len(trace.breadcrumbs), 2)
        self.assertEqual(trace.breadcrumbs[0]["category"], "log")
        self.assertEqual(trace.breadcrumbs[1]["category"], "query")
        self.assertIsNotNone(trace.breadcrumbs[0]["timestamp"])


if __name__ == "__main__":
    unittest.main()
