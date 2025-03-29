import unittest
from scapy.all import rdpcap
from pathlib import Path
from core.detector import ThreatDetector

class TestDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = ThreatDetector()
        test_data = Path(__file__).parent / "test_packets.pcap"
        cls.packets = rdpcap(str(test_data))

    def test_port_scan_detection(self):
        results = []
        for pkt in self.packets[:2]:  # First 2 are scan packets
            results.extend(self.detector.detect(pkt))
        self.assertTrue(any(r['type'] == 'Port Scan' for r in results))

    def test_malicious_dns(self):
        dns_pkt = self.packets[2]
        results = self.detector.detect(dns_pkt)
        self.assertTrue(any('evil.com' in r['evidence'] for r in results))

    def test_arp_spoof(self):
        arp_pkt = self.packets[3]
        results = self.detector.detect(arp_pkt)
        self.assertTrue(any(r['type'] == 'ARP Spoofing' for r in results))

if __name__ == "__main__":
    unittest.main()
