"""
Packet Capture for IDS.

Provides live packet capture via Scapy and a demo mode that replays
random samples from the NSL-KDD test set for development/demo purposes.
"""

import logging
import pickle
import random
import time
from pathlib import Path
from typing import Callable, Dict, Generator, Optional

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

# --- Port-to-NSL-KDD service mapping ---
PORT_SERVICE_MAP = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 37: "time", 42: "name", 43: "whois",
    53: "domain_u", 67: "bootps", 68: "bootpc",
    79: "finger", 80: "http", 109: "pop_2", 110: "pop_3",
    111: "sunrpc", 113: "auth", 119: "nntp", 123: "ntp_u",
    135: "netbios_ns", 137: "netbios_ns", 139: "netbios_ssn",
    143: "imap4", 161: "snmp", 179: "bgp", 389: "ldap",
    443: "http", 445: "netbios_ssn", 465: "smtp",
    514: "syslog", 515: "printer", 520: "rip",
    530: "courier", 540: "uucp", 587: "smtp",
    993: "imap4", 995: "pop_3",
    1080: "socks", 1433: "sql_net", 1521: "sql_net",
    3306: "sql_net", 5432: "sql_net", 5900: "vnc",
    6667: "IRC", 8080: "http", 8443: "http",
}

# TCP flag mapping to NSL-KDD flag values
TCP_FLAGS_MAP = {
    0x02: "S0",         # SYN only
    0x12: "S1",         # SYN-ACK
    0x10: "SF",         # ACK (established)
    0x11: "SF",         # FIN-ACK
    0x14: "RSTO",       # RST-ACK
    0x04: "REJ",        # RST
    0x18: "SF",         # PSH-ACK
    0x19: "SF",         # FIN-PSH-ACK
}


class PacketCapture:
    """Live packet capture using Scapy.

    Captures network packets, extracts NSL-KDD-compatible features,
    and yields them as feature dictionaries.

    Note: Requires root/sudo privileges for live capture.
    """

    def __init__(self, interface: str = "en0", timeout: int = 0):
        """Initialize packet capture.

        Args:
            interface: Network interface to sniff on.
            timeout: Capture timeout in seconds (0 = indefinite).
        """
        self.interface = interface
        self.timeout = timeout
        self._connection_table: Dict[str, dict] = {}

    def capture(self, callback: Optional[Callable] = None, count: int = 0) -> None:
        """Start capturing packets.

        Args:
            callback: Function called with feature dict for each packet.
            count: Number of packets to capture (0 = unlimited).
        """
        try:
            from scapy.all import sniff
        except ImportError:
            logger.error("Scapy not installed. Cannot perform live capture.")
            return

        logger.info("Starting live capture on %s...", self.interface)

        def _process(packet):
            features = self.extract_features(packet)
            if features and callback:
                callback(features)

        sniff(
            iface=self.interface,
            prn=_process,
            count=count,
            timeout=self.timeout if self.timeout > 0 else None,
            store=False,
        )

    def extract_features(self, packet) -> Optional[Dict]:
        """Extract NSL-KDD-compatible features from a raw packet.

        Args:
            packet: Scapy packet object.

        Returns:
            Feature dict with 41 NSL-KDD fields, or None if not IP.
        """
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
        except ImportError:
            return None

        if not packet.haslayer(IP):
            return None

        ip = packet[IP]

        # Protocol type
        if packet.haslayer(TCP):
            protocol_type = "tcp"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags_int = int(packet[TCP].flags)
            flag = TCP_FLAGS_MAP.get(flags_int, "OTH")
            payload_size = len(packet[TCP].payload) if packet[TCP].payload else 0
        elif packet.haslayer(UDP):
            protocol_type = "udp"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            flag = "SF"
            payload_size = len(packet[UDP].payload) if packet[UDP].payload else 0
        elif packet.haslayer(ICMP):
            protocol_type = "icmp"
            sport = 0
            dport = 0
            flag = "SF"
            payload_size = len(packet[ICMP].payload) if packet[ICMP].payload else 0
        else:
            return None

        # Map port to service
        service = PORT_SERVICE_MAP.get(dport, PORT_SERVICE_MAP.get(sport, "other"))

        features = {
            "duration": 0,
            "protocol_type": protocol_type,
            "service": service,
            "flag": flag,
            "src_bytes": int(ip.len) if hasattr(ip, "len") else 0,
            "dst_bytes": 0,
            "land": 1 if ip.src == ip.dst else 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 1,
            "srv_count": 1,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 1,
            "dst_host_srv_count": 1,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 1.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0,
        }

        return features


class DemoCapture:
    """Demo mode packet capture.

    Replays random samples from the processed NSL-KDD test set,
    simulating live traffic for the dashboard demo.
    """

    def __init__(self, delay: float = 2.0):
        """Initialize demo capture.

        Args:
            delay: Seconds between yielded samples.
        """
        self.delay = delay
        self._test_data = None
        self._feature_names = None
        self._load_test_data()

    def _load_test_data(self):
        """Load processed test data from disk."""
        pkl_path = PROCESSED_DIR / "processed_data.pkl"
        if pkl_path.exists():
            try:
                with open(pkl_path, "rb") as f:
                    data = pickle.load(f)
                self._test_data = data["X_test"]
                self._feature_names = data["feature_names"]
                logger.info("Demo mode: loaded %d test samples", len(self._test_data))
            except Exception as e:
                logger.warning("Failed to load test data: %s", e)
        else:
            logger.info("Demo mode: no processed data found, using synthetic samples")

    def generate(self) -> Generator[Dict, None, None]:
        """Yield feature dicts continuously for demo mode."""
        while True:
            if self._test_data is not None and len(self._test_data) > 0:
                idx = random.randint(0, len(self._test_data) - 1)
                sample = self._test_data[idx]
                features = {}
                for i, name in enumerate(self._feature_names):
                    features[name] = float(sample[i])
                yield features
            else:
                yield self._generate_synthetic()
            time.sleep(self.delay)

    @staticmethod
    def _generate_synthetic() -> Dict:
        """Generate a synthetic feature dict when no real data is available."""
        protocols = ["tcp", "udp", "icmp"]
        services = ["http", "smtp", "ftp_data", "ssh", "telnet", "domain_u"]
        flags = ["SF", "S0", "REJ", "RSTO", "S1"]

        return {
            "duration": random.randint(0, 5000),
            "protocol_type": random.choice(protocols),
            "service": random.choice(services),
            "flag": random.choice(flags),
            "src_bytes": random.randint(0, 50000),
            "dst_bytes": random.randint(0, 50000),
            "land": 0,
            "wrong_fragment": random.choices([0, 1], weights=[0.95, 0.05])[0],
            "urgent": 0,
            "hot": random.randint(0, 5),
            "num_failed_logins": random.choices([0, 1, 2], weights=[0.9, 0.08, 0.02])[0],
            "logged_in": random.choice([0, 1]),
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": random.randint(1, 500),
            "srv_count": random.randint(1, 500),
            "serror_rate": round(random.uniform(0, 1), 2),
            "srv_serror_rate": round(random.uniform(0, 1), 2),
            "rerror_rate": round(random.uniform(0, 0.5), 2),
            "srv_rerror_rate": round(random.uniform(0, 0.5), 2),
            "same_srv_rate": round(random.uniform(0, 1), 2),
            "diff_srv_rate": round(random.uniform(0, 1), 2),
            "srv_diff_host_rate": round(random.uniform(0, 1), 2),
            "dst_host_count": random.randint(0, 255),
            "dst_host_srv_count": random.randint(0, 255),
            "dst_host_same_srv_rate": round(random.uniform(0, 1), 2),
            "dst_host_diff_srv_rate": round(random.uniform(0, 1), 2),
            "dst_host_same_src_port_rate": round(random.uniform(0, 1), 2),
            "dst_host_srv_diff_host_rate": round(random.uniform(0, 1), 2),
            "dst_host_serror_rate": round(random.uniform(0, 0.5), 2),
            "dst_host_srv_serror_rate": round(random.uniform(0, 0.5), 2),
            "dst_host_rerror_rate": round(random.uniform(0, 0.5), 2),
            "dst_host_srv_rerror_rate": round(random.uniform(0, 0.5), 2),
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    print("Running demo capture (3 samples)...")
    demo = DemoCapture(delay=0.5)
    gen = demo.generate()
    for i in range(3):
        sample = next(gen)
        print(f"Sample {i + 1}: {len(sample)} features, protocol={sample.get('protocol_type', 'N/A')}")
