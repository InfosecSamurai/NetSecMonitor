import argparse
from core.packet_sniffer import PacketSniffer
from utils.reporter import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description="Network Security Monitor")
    parser.add_argument("-i", "--interface", help="Network interface")
    parser.add_argument("-c", "--count", type=int, default=0, help="Packet count limit")
    parser.add_argument("--http-only", action="store_true", help="Monitor HTTP only")
    args = parser.parse_args()

    sniffer = PacketSniffer(args.interface)
    
    try:
        if args.http_only:
            sniffer.capture_http()
        else:
            sniffer.start(args.count)
    except KeyboardInterrupt:
        print("\n[+] Generating final report...")
        ReportGenerator().generate()

if __name__ == "__main__":
    main()
