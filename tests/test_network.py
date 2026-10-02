import json


def test_service_reachable_passes():
    assert "localhost" == "localhost"


def test_timeout_host_a():
    raise TimeoutError("Connection to 10.0.0.14:443 timed out after 5.01s")


def test_timeout_host_b():
    raise TimeoutError("Connection to 10.0.0.22:443 timed out after 5.03s")


def test_connection_refused():
    raise ConnectionRefusedError("Connection refused: 10.0.0.5:8080")


def test_malformed_json_a():
    json.loads("{bad")


def test_malformed_json_b():
    json.loads("{oops")