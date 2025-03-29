import json
from datetime import datetime
from pathlib import Path
import matplotlib.pyplot as plt

class SecurityReporter:
    def __init__(self):
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
        
    def generate(self, findings, report_format="txt"):
        """Generate security reports in multiple formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if report_format == "txt":
            self._generate_txt(findings, timestamp)
        elif report_format == "json":
            self._generate_json(findings, timestamp)
        self._generate_visualization(findings, timestamp)

    def _generate_txt(self, findings, timestamp):
        report_path = self.report_dir / f"report_{timestamp}.txt"
        with open(report_path, "w") as f:
            f.write(f"Security Report - {timestamp}\n")
            f.write("="*40 + "\n")
            for finding in findings:
                f.write(f"\nType: {finding['type']}\n")
                f.write(f"Source: {finding['source']}\n")
                f.write(f"Timestamp: {finding.get('timestamp', 'N/A')}\n")
                f.write(f"Details: {finding['evidence']}\n")

    def _generate_json(self, findings, timestamp):
        report_path = self.report_dir / f"report_{timestamp}.json"
        with open(report_path, "w") as f:
            json.dump({
                "metadata": {
                    "generated_at": timestamp,
                    "analyst": "NetSecMonitor v1.0"
                },
                "findings": findings
            }, f, indent=2)

    def _generate_visualization(self, findings, timestamp):
        if not findings:
            return
            
        threat_types = [f['type'] for f in findings]
        plt.figure(figsize=(10, 4))
        plt.hist(threat_types, bins=len(set(threat_types)))
        plt.title("Threat Type Distribution")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(self.report_dir / f"threats_{timestamp}.png")
        plt.close()
