import socket
import urllib.request


def test_http_500_stack_trace(http_server):
    urllib.request.urlopen(f"{http_server}/error500", timeout=3)


def test_partial_response(http_server):
    urllib.request.urlopen(f"{http_server}/partial", timeout=3).read()


def test_connection_reset_midstream(reset_server):
    host, port = reset_server
    with socket.create_connection((host, port), timeout=3) as s:
        s.sendall(b"hello")
        s.recv(1024)


def test_slow_but_successful(http_server):
    # Negative control: slow (1s) but within the 3s timeout, so it must PASS.
    resp = urllib.request.urlopen(f"{http_server}/slow", timeout=3)
    assert resp.read() == b"ok"