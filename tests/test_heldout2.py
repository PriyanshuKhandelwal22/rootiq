import json

from rootiq.collector.netprobe import observed_http_get


def test_http_404_missing_resource(http_server):
    observed_http_get(f"{http_server}/missing")


def test_http_503_upstream_refused(http_server):
    observed_http_get(f"{http_server}/unavailable")


def test_wrong_field_type(http_server):
    data = json.loads(observed_http_get(f"{http_server}/wrongtype"))
    total = data["count"] + 1  # "count" arrives as a string, so this raises TypeError


def test_response_slower_than_timeout(http_server):
    observed_http_get(f"{http_server}/hang", timeout=2)