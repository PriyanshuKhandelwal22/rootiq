import socket
import urllib.request

from rootiq.collector.netprobe import observe_socket, observed_http_get


def test_http_500_stack_trace(http_server):
    observed_http_get(f"{http_server}/error500")


def test_partial_response(http_server):
    observed_http_get(f"{http_server}/partial")


def test_connection_reset_midstream(reset_server):
    host, port = reset_server
    with socket.create_connection((host, port), timeout=3) as s:
        with observe_socket(host, port, "read"):
            s.sendall(b"hello")
            s.recv(1024)