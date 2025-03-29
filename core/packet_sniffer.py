from scapy.all import sniff, conf
from scapy.layers import http
from core.analyzer import PacketAnalyzer

class PacketSniffer:
    def __init__(self, interface=None):
        self.interface = interface or conf.iface
        self.analyzer = PacketAnalyzer()

    def start(self, packet_count=0):
        """Start sniffing with optional packet count limit"""
        sniff(
            iface=self.interface,
            prn=self.analyzer.process,
            store=False,
            count=packet_count
        )

    def capture_http(self):
        """Specialized HTTP traffic capture"""
        sniff(
            iface=self.interface,
            prn=self.analyzer.process_http,
            lfilter=lambda p: p.haslayer(http.HTTPRequest),
            store=False
        )
