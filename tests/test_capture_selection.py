import unittest

from tools.packclient_pcap import analyze_capture, format_timeline
from test_pcap_tooling import ethernet_ipv4_tcp, pcap


class CaptureSelectionTests(unittest.TestCase):
    def test_all_tcp_includes_diagnostic_flow_without_classifying_it(self):
        packet = ethernet_ipv4_tcp(b"ordinary-tcp-payload", 1000)
        capture = pcap([(1_700_000_000, 100, packet)])

        default = analyze_capture(capture)
        self.assertEqual(default["included_flow_count"], 0)
        self.assertEqual(default["flows"], [])

        diagnostic = analyze_capture(capture, include_all_tcp=True)
        self.assertEqual(diagnostic["included_flow_count"], 1)
        self.assertEqual(len(diagnostic["flows"]), 1)
        flow = diagnostic["flows"][0]
        self.assertEqual(flow["direction_basis"], "unknown")
        self.assertEqual(flow["status"], "rejected/malformed")
        self.assertNotIn("classification", flow)

        timeline = format_timeline(diagnostic)
        self.assertIn("included_flows=1", timeline)
        self.assertNotIn("packclient_flows=", timeline)


if __name__ == "__main__":
    unittest.main()
