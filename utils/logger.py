import logging
from datetime import datetime
from pathlib import Path

class ThreatLogger:
    def __init__(self):
        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        self._setup_logging()

    def _setup_logging(self):
        logging.basicConfig(
            filename=self.log_dir/f"sec_{datetime.now().strftime('%Y%m%d')}.log",
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.WARNING
        )
        self.logger = logging.getLogger('netsec')

    def log(self, event, source, details):
        """Unified logging method"""
        log_entry = f"{event} from {source}: {details}"
        self.logger.warning(log_entry)
        # Also print to console with color
        print(f"\033[91m[!] {log_entry}\033[0m")  # Red for alerts
