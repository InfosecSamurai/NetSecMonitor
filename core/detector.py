from collections import defaultdict
from datetime import datetime, timedelta
import json
from pathlib import Path
from scapy.all import IP, TCP, UDP, ICMP, ARP
from typing import Dict, List
from threading import Lock

class ThreatDetector:
    def __init__(self):
        self.connection_tracker = defaultdict(list)
        self._lock = Lock()
        self.load_rules()
        
    def load_rules(self):
        """Load detection rules from JSON config"""
        rules_path = Path(__file__).parent.parent / 'config' / 'threat_patterns.json'
        with open(rules_path) as f:
            self.rules = json.load(f)
        
        self.rates = {
            'tcp_syn': defaultdict(int),
            'icmp': defaultdict(int),
            'dns': defaultdict(int)
        }
        self.last_reset = datetime.now()

    def detect(self, packet) -> List[Dict]:
        """Thread-safe threat detection"""
        threats = []
        
        with self._lock:
            if packet.haslayer(TCP):
                threats.extend(self._detect_tcp(packet))
            if packet.haslayer(ICMP):
                threats.extend(self._detect_icmp(packet))
            if packet.haslayer(ARP):
                threats.extend(self._detect_arp(packet))
            if datetime.now() - self.last_reset > timedelta(hours=1):
                self._reset_counters()
                
        return threats

    def _detect_tcp(self, packet) -> List[Dict]:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        
        if dst_port in self.rules['port_scanning']:
            self.connection_tracker[src_ip].append({
                'timestamp': datetime.now(),
                'port': dst_port,
                'flags': packet[TCP].flags
            })
            
            recent = [c for c in self.connection_tracker[src_ip] 
                    if datetime.now() - c['timestamp'] < timedelta(minutes=5)]
            if len({c['port'] for c in recent}) >= 3:
                return [{
                    'type': 'Port Scan',
                    'source': src_ip,
                    'severity': 'High',
                    'evidence': f"Scanned ports: {[c['port'] for c in recent]}"
                }]
        return []

    def _detect_icmp(self, packet) -> List[Dict]:
        src_ip = packet[IP].src
        self.rates['icmp'][src_ip] += 1
        
        if self.rates['icmp'][src_ip] > self.rules['rate_limits'].get('icmp', 100):
            return [{
                'type': 'ICMP Flood',
                'source': src_ip,
                'severity': 'Medium',
                'evidence': f"Rate: {self.rates['icmp'][src_ip]} packets/min"
            }]
        return []

    def _reset_counters(self):
        """Reset all rate counters"""
        for counter in self.rates.values():
            counter.clear()
        self.last_reset = datetime.now()
