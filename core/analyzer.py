import json
from pathlib import Path
from scapy.layers import inet, dns
from utils.logger import ThreatLogger

class PacketAnalyzer:
    def __init__(self):
        self.logger = ThreatLogger()
        with open(Path(__file__).parent.parent/'config'/'threat_patterns.json') as f:
            self.threat_db = json.load(f)

    def process(self, packet):
        """Main packet processing router"""
        if packet.haslayer(inet.IP):
            self._analyze_ip(packet)
        if packet.haslayer(dns.DNSQR):
            self._analyze_dns(packet)

    def _analyze_ip(self, packet):
        """IP layer analysis"""
        # ... (TCP/UDP/ICMP analysis logic)

    def _analyze_dns(self, packet):
        """DNS query analysis"""
        query = packet[dns.DNSQR].qname.decode()
        if any(domain in query for domain in self.threat_db["suspicious_domains"]):
            self.logger.log(
                event="Malicious DNS Query",
                source=packet[inet.IP].src,
                details=f"Query to {query}"
            )
