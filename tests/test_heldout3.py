import socket

from rootiq.collector.netprobe import observe_socket, observed_http_get


def test_http_401_invalid_token(http_server):
    observed_http_get(f"{http_server}/unauthorized")


def test_http_429_rate_limited(http_server):
    observed_http_get(f"{http_server}/ratelimited")


def test_unresolvable_hostname():
    # ".invalid" is reserved and never resolves
    with observe_socket("nonexistent.invalid", 80, "connect"):
        socket.create_connection(("nonexistent.invalid", 80), timeout=3)


def test_server_closes_without_reply(http_server):
    observed_http_get(f"{http_server}/closeearly")