import argparse
from scapy.all import rdpcap
from core.packet_sniffer import PacketSniffer
from utils.reporter import SecurityReporter

def analyze_pcap(pcap_file):
    """Analyze existing PCAP file"""
    print(f"[*] Analyzing PCAP file: {pcap_file}")
    packets = rdpcap(pcap_file)
    sniffer = PacketSniffer()
    findings = []
    
    for packet in packets:
        findings.extend(sniffer.analyzer.process(packet))
    
    SecurityReporter().generate(findings, "json")
    print(f"[+] Analysis complete. Report generated.")

def main():
    parser = argparse.ArgumentParser(description="Network Security Monitor")
    parser.add_argument("-i", "--interface", help="Network interface")
    parser.add_argument("-r", "--read-pcap", help="Analyze existing PCAP file")
    parser.add_argument("-c", "--count", type=int, default=0, help="Packet count limit")
    args = parser.parse_args()

    if args.read_pcap:
        analyze_pcap(args.read_pcap)
        return

    sniffer = PacketSniffer(args.interface)
    try:
        sniffer.start(args.count)
    except KeyboardInterrupt:
        print("\n[+] Generating final report...")
        SecurityReporter().generate(sniffer.findings)

if __name__ == "__main__":
    main()
