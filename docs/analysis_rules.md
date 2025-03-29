# Threat Detection Rules

## Core Detection Patterns

### 1. Port Scanning
```yaml
rule:
  name: tcp_port_scan
  ports: [21, 22, 80, 443, 3389]
  threshold: 3_unique_ports/60s
  severity: high
```

### 2. ARP Spoofing
```json
{
  "rule_name": "arp_spoof_detect",
  "validation": "mac_ip_binding",
  "severity": "critical",
  "response": ["alert", "log"]
}
```

### 3. Suspicious DNS
| Pattern            | Example               | Severity |
|--------------------|-----------------------|----------|
| Known bad domains  | malware.com           | High     |
| DNS tunneling      | long.base64.domain    | Medium   |
| NXDOMAIN flood     | random123.example     | Low      |

## Rate Limits
- ICMP: 100 packets/second
- TCP SYN: 50 packets/minute
- DNS queries: 30 requests/minute
