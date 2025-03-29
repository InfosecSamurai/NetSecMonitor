# NetSecMonitor 🌐🔍  
**Enterprise-Ready Network Traffic Analysis & Threat Detection System**  

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Scapy](https://img.shields.io/badge/Scapy-2.4.5%2B-orange)
![License](https://img.shields.io/badge/License-MIT-green)
![Thread-Safe](https://img.shields.io/badge/Thread-Safe-brightgreen)

## 📌 Overview  
A real-time network security monitoring system that:  
- Captures and analyzes traffic at packet level  
- Detects 15+ threat patterns (DDoS, ARP spoofing, port scans, etc.)  
- Generates actionable security reports  
- Supports both live traffic and PCAP analysis  

**Perfect for**:  
- SOC analysts  
- Network administrators  
- Cybersecurity students  
- Red/Blue team exercises  

## 🚀 Features  
| Module | Capabilities |  
|--------|-------------|  
| **Packet Sniffer** | Live capture on any interface |  
| **Protocol Analyzer** | Deep inspection of TCP/UDP/ICMP/DNS/HTTP |  
| **Threat Engine** | Detects:<br>• Port scanning<br>• ARP spoofing<br>• Suspicious DNS<br>• ICMP floods |  
| **Reporting** | Generates:<br>• Console alerts<br>• Log files<br>• JSON/TXT reports<br>• Visualizations |  

## 🛠️ Installation  

### Prerequisites  
```bash
# Linux
sudo apt install libpcap-dev tshark

# macOS
brew install libpcap wireshark
```

### Setup  
```bash
git clone https://github.com/InfosecSamurai/NetSecMonitor.git
cd NetSecMonitor
pip install -r requirements.txt

# Generate test data
python tests/generate_test_pcap.py
```

## 🖥️ Usage  

### Live Traffic Analysis  
```bash
# Basic capture (CTRL+C to stop)
sudo python netsec.py -i eth0

# Limited packet capture
sudo python netsec.py -i wlan0 -c 500

# HTTP-only monitoring
sudo python netsec.py -i eth0 --http-only
```

### PCAP File Analysis  
```bash
python netsec.py -r suspicious_traffic.pcap
```

### Advanced Options  
| Argument | Description | Default |  
|----------|-------------|---------|  
| `-i INTERFACE` | Network interface | System default |  
| `-c COUNT` | Packet limit | 0 (unlimited) |  
| `-r PCAP_FILE` | Analyze existing PCAP | None |  
| `--http-only` | Monitor HTTP only | False |  

## 📂 Project Structure  
```
NetSecMonitor/
├── config/               # Detection rules and patterns
│   └── threat_patterns.json
├── core/                # Main processing logic
│   ├── packet_sniffer.py
│   ├── analyzer.py
│   └── detector.py
├── utils/               # Support modules
│   ├── logger.py
│   └── reporter.py
├── tests/               # Unit tests
│   ├── test_packets.pcap
│   └── test_analysis.py
├── docs/                # Documentation
│   └── analysis_rules.md
├── requirements.txt
├── README.md
└── netsec.py            # Main entry point
```

## 🧪 Testing  
```bash
# Run all unit tests
python -m unittest discover tests/

# Test specific module
python -m unittest tests/test_analysis.py
```

## 🛡️ Detection Capabilities  

### Supported Threats  
| Threat Type | Detection Method | Sample Alert |
|------------|------------------|--------------|
| Port Scanning | SYN flood detection | `[!] Port scan detected from 192.168.1.100` |
| ARP Spoofing | MAC/IP mismatch | `[!] ARP spoofing: 00:11:22:aa:bb:cc pretending to be 10.0.0.1` |
| DNS Exfiltration | Known malicious domains | `[!] DNS query to malware.com from 10.0.0.15` |

## 📊 Sample Report  
```json
{
  "type": "Port Scan",
  "source": "192.168.1.100",
  "severity": "High",
  "evidence": "Scanned ports: [22, 80, 443]",
  "timestamp": "2023-08-20T14:30:45"
}
```

![Threat Visualization](https://via.placeholder.com/600x200?text=Sample+Threat+Distribution+Chart)

## 🤝 Contribution  
1. Fork the repository  
2. Create your feature branch (`git checkout -b feature/improvement`)  
3. Commit changes (`git commit -m 'Add new detection pattern'`)  
4. Push to branch (`git push origin feature/improvement`)  
5. Open a Pull Request  

## 📜 License  
MIT License - See [LICENSE](LICENSE) for details  

## 🔍 Looking Ahead  
| Planned Feature | Status |
|----------------|--------|
| Machine Learning Anomaly Detection | Planned |
| Real-Time Slack/Email Alerts | In Progress |
| Docker Support | Planned |
| SIEM Integration | Research Phase |
