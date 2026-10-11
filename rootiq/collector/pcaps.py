import threading
import time
from collections import defaultdict
from pathlib import Path

from scapy.all import IP, TCP, AsyncSniffer, conf, wrpcap

conf.use_pcap = True

FLAG_NAMES = {"S": "SYN", "SA": "SYN-ACK", "A": "ACK", "FA": "FIN-ACK",
              "F": "FIN", "R": "RST", "RA": "RST-ACK", "PA": "PSH-ACK"}


def _loopback():
    for iface in conf.ifaces.values():
        text = f"{iface.name} {getattr(iface, 'description', '')}".lower()
        if "loopback" in text:
            return iface
    return None


class PacketCapture:
    """Captures loopback TCP traffic in the background while tests run."""

    def __init__(self):
        self.sniffer = None
        self.packets = []
        self.error = None

    def start(self) -> None:
        iface = _loopback()
        if iface is None:
            self.error = "no loopback interface (is Npcap installed?)"
            return
        try:
            self.sniffer = AsyncSniffer(iface=iface, filter="tcp", store=True)
            self.sniffer.start()
            time.sleep(1.0)  # give the sniffer time to attach before tests start
        except Exception as e:  # capture is optional, never break a test run
            self.error = f"{type(e).__name__}: {e}"
            self.sniffer = None

    def stop(self, pcap_path: Path) -> dict:
        if self.sniffer is not None:
            time.sleep(0.3)  # let trailing packets arrive
            try:
                self.packets = list(self.sniffer.stop() or [])
            except Exception as e:
                self.error = f"{type(e).__name__}: {e}"
        if self.packets:
            wrpcap(str(pcap_path), self.packets)
        return {
            "pcap_file": str(pcap_path) if self.packets else None,
            "packet_count": len(self.packets),
            "error": self.error,
            "flows": self._flows(),
        }

    def _flows(self) -> dict:
        """Summarize packets per server port: which flags were seen, in order."""
        by_port = defaultdict(list)
        for p in self.packets:
            if not p.haslayer(TCP):
                continue
            tcp = p[TCP]
            flags = str(tcp.flags)
            for port in (tcp.sport, tcp.dport):
                by_port[port].append({
                    "t": round(float(p.time), 4),
                    "src": f"{p[IP].src}:{tcp.sport}",
                    "dst": f"{p[IP].dst}:{tcp.dport}",
                    "flags": flags,
                })
        return {
            str(port): {
                "packets": len(pkts),
                "flag_sequence": [p["flags"] for p in pkts],
                "saw_syn": any(p["flags"] == "S" for p in pkts),
                "saw_synack": any(p["flags"] == "SA" for p in pkts),
                "saw_rst": any("R" in p["flags"] for p in pkts),
            }
            for port, pkts in by_port.items()
        }