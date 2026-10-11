import socket
import threading
import time

from scapy.all import TCP, conf, sniff

conf.use_pcap = True  # use Npcap so that BPF filters work on Windows


def find_loopback():
    for iface in conf.ifaces.values():
        text = f"{iface.name} {getattr(iface, 'description', '')}".lower()
        if "loopback" in text:
            return iface
    return None


lo = find_loopback()
print("loopback interface:", lo)
if lo is None:
    print(conf.ifaces)
    raise SystemExit("No loopback interface found. Is Npcap installed?")

srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(1)
port = srv.getsockname()[1]


def connect_later():
    time.sleep(1)
    socket.create_connection(("127.0.0.1", port), timeout=2).close()


threading.Thread(target=connect_later).start()
packets = sniff(iface=lo, filter=f"tcp port {port}", timeout=3)

print(f"captured {len(packets)} packets on port {port}")
for p in packets:
    if p.haslayer(TCP):
        print(" ", p[TCP].flags, p.summary())