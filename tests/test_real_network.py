import socket

from rootiq.collector.netprobe import observe_socket


def test_real_connect_passes(listening_server):
    host, port = listening_server
    with observe_socket(host, port, "connect"):
        socket.create_connection((host, port), timeout=2).close()


def test_real_connection_refused(closed_port):
    # Windows can take ~2s to report a refused loopback connection,
    # so the timeout must be longer than that.
    host, port = closed_port
    with observe_socket(host, port, "connect"):
        socket.create_connection((host, port), timeout=5)


def test_real_read_timeout(listening_server):
    host, port = listening_server
    with socket.create_connection((host, port), timeout=2) as s:
        s.settimeout(0.5)
        with observe_socket(host, port, "read"):
            s.recv(1024)  # server never replies, so this really times out
