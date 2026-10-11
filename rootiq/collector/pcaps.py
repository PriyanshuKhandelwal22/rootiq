import socket
import time
from collections import defaultdict
from pathlib import Path

from scapy.all import IP, TCP, AsyncSniffer, conf, wrpcap

from rootiq.collector.netprobe import BLACKHOLE_HOST

conf.use_pcap = True


def _loopback():
    for iface in conf.ifaces.values():
        text = f"{iface.name} {getattr(iface, 'description', '')}".lower()
        if "loopback" in text:
            return iface
    return None


def _outbound_iface():
    """Interface Windows would use to reach the blackhole (no packets are sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((BLACKHOLE_HOST, 80))
        local_ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
    for iface in conf.ifaces.values():
        if getattr(iface, "ip", None) == local_ip:
            return iface
    return None


class PacketCapture:
    """Background capture: loopback TCP, plus outbound TCP to the blackhole host."""

    def __init__(self):
        self.sniffers = []
        self.packets = []
        self.errors = []

    def _add(self, iface, bpf, label):
        if iface is None:
            self.errors.append(f"{label}: interface not found")
            return
        try:
            sn = AsyncSniffer(iface=iface, filter=bpf, store=True)
            sn.start()
            self.sniffers.append(sn)
        except Exception as e:  # capture is optional, never break a test run
            self.errors.append(f"{label}: {type(e).__name__}: {e}")

    def start(self) -> None:
        self._add(_loopback(), "tcp", "loopback")
        self._add(_outbound_iface(), f"tcp and host {BLACKHOLE_HOST}", "outbound")
        if self.sniffers:
            time.sleep(1.0)  # let the sniffers attach before tests start

    def stop(self, pcap_path: Path) -> dict:
        if self.sniffers:
            time.sleep(0.3)  # let trailing packets arrive
        for sn in self.sniffers:
            try:
                self.packets += list(sn.stop() or [])
            except Exception as e:
                self.errors.append(f"stop: {type(e).__name__}: {e}")
        self.packets.sort(key=lambda p: float(p.time))
        if self.packets:
            wrpcap(str(pcap_path), self.packets)
        return {
            "pcap_file": str(pcap_path) if self.packets else None,
            "packet_count": len(self.packets),
            "error": "; ".join(self.errors) or None,
            "flows": self._flows(),
        }

    def _flows(self) -> dict:
        by_port = defaultdict(list)
        for p in self.packets:
            if not (p.haslayer(TCP) and p.haslayer(IP)):
                continue
            tcp = p[TCP]
            flags = str(tcp.flags)
            for port in (tcp.sport, tcp.dport):
                by_port[port].append({"flags": flags})
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