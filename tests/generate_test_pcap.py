from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR

def generate_test_data():
    """Generate test PCAP with:
    - Port scan packets
    - Malicious DNS query
    - ARP spoofing attempt"""
    packets = [
        # Port scan (TCP SYN)
        IP(dst="192.168.1.1")/TCP(dport=22, flags="S"),
        IP(dst="192.168.1.1")/TCP(dport=80, flags="S"),
        IP(dst="192.168.1.1")/TCP(dport=443, flags="S"),
        
        # Malicious DNS
        IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname="malware.com")),
        
        # ARP spoofing
        Ether(src="00:11:22:33:44:55")/ARP(psrc="192.168.1.100", pdst="192.168.1.1")
    ]
    wrpcap("tests/test_packets.pcap", packets)

if __name__ == "__main__":
    generate_test_data()
