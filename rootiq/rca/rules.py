import re

# First matching rule wins, so keep specific rules above general ones.
RULES = [
    {
        "id": "R01",
        "error_types": {"ModuleNotFoundError", "ImportError"},
        "root_cause": "missing_dependency",
        "confidence": 0.90,
        "alternatives": ["wrong virtual environment", "package version mismatch"],
        "next_tests": ["pip list in the active environment",
                       "compare against requirements.txt"],
    },
    {
        "id": "R02",
        "error_types": {"ConnectionRefusedError"},
        "template_regex": r"connection refused",
        "root_cause": "service_down",
        "confidence": 0.70,
        "alternatives": ["wrong host or port", "firewall rejecting the connection"],
        "next_tests": ["check the service process is running",
                       "verify the port is listening (netstat -ano)"],
    },
    {
        "id": "R03",
        "error_types": {"TimeoutError"},
        "template_regex": r"timed out",
        "root_cause": "network_path_or_service_unavailable",
        "confidence": 0.60,
        "alternatives": ["firewall dropping packets", "destination overloaded",
                         "DNS or routing problem"],
        "next_tests": ["ping the destination", "check the destination port",
                       "capture packets and look for SYN without SYN-ACK"],
    },
    {
        "id": "R04",
        "error_types": {"JSONDecodeError"},
        "root_cause": "input_validation",
        "confidence": 0.75,
        "alternatives": ["upstream service returned an error page",
                         "response truncated in transit"],
        "next_tests": ["log the raw response body",
                       "validate the payload against the expected schema"],
    },
    {
        "id": "R05",
        "error_types": {"KeyError"},
        "root_cause": "missing_field_in_response",
        "confidence": 0.60,
        "alternatives": ["API contract changed", "application defect"],
        "next_tests": ["print the full response object",
                       "compare against the API schema or a previous passing run"],
    },
    {
        "id": "R06",
        "error_types": {"AssertionError"},
        "root_cause": "application_defect",
        "confidence": 0.50,
        "alternatives": ["wrong expected value in the test", "environment difference"],
        "next_tests": ["check the actual vs expected values",
                       "rerun to rule out flakiness"],
    },
]


def _matches(rule: dict, error_type: str, template: str) -> bool:
    short = error_type.rsplit(".", 1)[-1]  # json.decoder.JSONDecodeError -> JSONDecodeError
    if short not in rule["error_types"]:
        return False
    regex = rule.get("template_regex")
    return re.search(regex, template, re.I) is not None if regex else True


def diagnose(group: list[dict]) -> dict:
    """Diagnose one fingerprint group (a list of normalized failures)."""
    first = group[0]
    evidence = [
        f"E1: error_type = {first['error_type']}",
        f"E2: normalized message = {first['template']}",
        f"E3: same fingerprint in {len(group)} test(s)",
    ]
    for rule in RULES:
        if _matches(rule, first["error_type"], first["template"]):
            return {
                "fingerprint": first["fingerprint"],
                "affected_tests": [f["test_id"] for f in group],
                "root_cause": rule["root_cause"],
                "confidence": rule["confidence"],
                "rule_id": rule["id"],
                "evidence": evidence,
                "alternatives": rule["alternatives"],
                "next_tests": rule["next_tests"],
            }
    return {
        "fingerprint": first["fingerprint"],
        "affected_tests": [f["test_id"] for f in group],
        "root_cause": "unknown_insufficient_evidence",
        "confidence": 0.0,
        "rule_id": None,
        "evidence": evidence,
        "alternatives": [],
        "next_tests": ["collect more evidence (logs, metrics, packet capture)"],
    }


def _describe(e: dict) -> str:
    if e.get("type") == "http":
        text = f"{e['id']}: GET {e['url']} -> status {e['status']} ({e['outcome']})"
        if e["outcome"] == "incomplete_read":
            text += f", received {e['bytes_received']} of {e['bytes_expected']} bytes"
        excerpt = (e.get("body_excerpt") or "").strip()
        if excerpt:
            text += f", body ends: {excerpt.splitlines()[-1]}"
        return text
    return (f"{e['id']}: {e['phase']} to {e['host']}:{e['port']} -> "
            f"{e['outcome']} after {e['elapsed_ms']} ms")

def _http_rule(http_ev: list[dict]) -> tuple[dict, list[dict]] | None:
    """Rules driven by HTTP evidence. Returns (rule, evidence used) or None."""
    for e in http_ev:
        if e["outcome"] == "incomplete_read":
            return ({"id": "E05", "root_cause": "truncated_response",
                     "confidence": 0.85,
                     "alternatives": ["server crashed mid-response",
                                      "proxy or network cut the connection"],
                     "next_tests": ["compare Content-Length with bytes received",
                                    "check server logs for a crash at that time"]}, [e])
        if e["outcome"] == "http_error" and e["status"] and e["status"] >= 500:
            traced = "Traceback" in (e.get("body_excerpt") or "")
            return ({"id": "E06",
                     "root_cause": "application_defect" if traced else "server_error_unknown_cause",
                     "confidence": 0.85 if traced else 0.50,
                     "alternatives": ["dependency failure behind the server",
                                      "bad input triggering an unhandled case"],
                     "next_tests": ["inspect the stack trace location in server code",
                                    "replay the request with known-good input"]}, [e])
    return None

def diagnose_with_evidence(group: list[dict], evidence: list[dict],
                           flows: dict | None = None) -> dict:
    """Prefer observed socket outcomes over error-message matching."""
    d = diagnose(group)
    ids = {f["test_id"] for f in group}
    socks = [e for e in evidence
             if e.get("type") == "socket" and e.get("test_id") in ids]
    https = [e for e in evidence
             if e.get("type") == "http" and e.get("test_id") in ids]
    if not socks and not https:
        return d  # no observations, so fall back to the string rules
    def pick(phase, outcome):
        return [e for e in socks if e["phase"] == phase and e["outcome"] == outcome]

    refused = pick("connect", "refused")
    conn_timeout = pick("connect", "timeout")
    dns = [e for e in socks if e["outcome"] == "dns_error"]
    connect_ok = pick("connect", "ok")
    read_timeout = [
        e for e in pick("read", "timeout")
        if any(c["test_id"] == e["test_id"] and c["port"] == e["port"]
               for c in connect_ok)
    ]

    reset = pick("read", "reset") + pick("connect", "reset")
    http_hit = _http_rule(https)

    if http_hit:
        rule, used = http_hit
    elif reset:
        used, rule = reset, {
            "id": "E07", "root_cause": "connection_reset", "confidence": 0.80,
            "alternatives": ["server process crashed", "firewall or proxy reset the flow",
                             "server aborted on invalid request"],
            "next_tests": ["check server logs for a crash or abort",
                           "capture packets and see which side sent the RST"]}
    elif refused:
        used, rule = refused, {
            "id": "E01", "root_cause": "service_down", "confidence": 0.85,
            "alternatives": ["wrong port in test configuration",
                             "firewall actively rejecting (REJECT rule)"],
            "next_tests": ["check the service process is running",
                           f"netstat -ano | findstr :{refused[0]['port']}"]}
    elif read_timeout:
        used = [c for c in connect_ok
                if c["test_id"] == read_timeout[0]["test_id"]] + read_timeout
        rule = {
            "id": "E02", "root_cause": "service_unresponsive", "confidence": 0.80,
            "alternatives": ["application hung or deadlocked",
                             "client timeout shorter than normal response time",
                             "server overloaded"],
            "next_tests": ["inspect server logs for the same time window",
                           "retry with a longer read timeout"]}
    elif conn_timeout:
        used, rule = conn_timeout, {
            "id": "E03", "root_cause": "network_path_or_firewall", "confidence": 0.65,
            "alternatives": ["destination host down", "routing problem"],
            "next_tests": ["capture packets and look for SYN without SYN-ACK",
                           "ping the destination"]}
    elif dns:
        used, rule = dns, {
            "id": "E04", "root_cause": "dns_failure", "confidence": 0.85,
            "alternatives": ["typo in hostname", "resolver unreachable"],
            "next_tests": ["nslookup the hostname", "check DNS server settings"]}
    else:
        return d

    d["string_rule_said"] = d["root_cause"]
    d["root_cause"] = rule["root_cause"]
    d["confidence"] = rule["confidence"]
    d["rule_id"] = rule["id"]
    d["alternatives"] = rule["alternatives"]
    d["next_tests"] = rule["next_tests"]
    d["evidence"] = d["evidence"] + [_describe(e) for e in used]
    d["evidence_ids"] = [e["id"] for e in used]
    if flows is not None:
        checks = [(e["id"], packet_check(e, flows)) for e in used if "port" in e]
        for ev_id, c in checks:
            if c["status"] == "n/a":
                continue
            d["evidence"].append(f"PKT({ev_id}): {c['status']}: {c['note']}")
        if any(c["status"] == "confirmed" for _, c in checks):
            d["confidence"] = min(0.95, d["confidence"] + 0.10)
        if any(c["status"] == "inconsistent" for _, c in checks):
            d["confidence"] = max(0.30, d["confidence"] - 0.25)
            d["evidence"].append("WARNING: wire evidence disagrees with app evidence")
    return d

def packet_check(socket_ev: dict, flows: dict) -> dict:
    """Compare what Python observed with what the wire showed, for one socket record."""
    flow = (flows or {}).get(str(socket_ev["port"]))
    if flow is None:
        return {"status": "no_packets", "note": "no packets captured for this port"}
    seq = flow["flag_sequence"]
    outcome = socket_ev["outcome"]
    if outcome == "refused":
        if flow["saw_rst"]:
            return {"status": "confirmed",
                    "note": f"{seq.count('S')} SYN(s) answered by RST; nothing listening"}
        return {"status": "inconsistent",
                "note": "app saw refused but no RST on the wire (capture gap or proxy?)"}
    if outcome == "timeout" and socket_ev["phase"] == "connect":
        if flow["saw_syn"] and not flow["saw_synack"] and not flow["saw_rst"]:
            return {"status": "confirmed",
                    "note": "SYN sent, no SYN-ACK or RST came back; packets dropped"}
        return {"status": "inconsistent",
                "note": "connect timeout but the wire shows a reply"}
    if outcome == "ok" and socket_ev["phase"] == "connect":
        if flow["saw_synack"]:
            return {"status": "confirmed", "note": "3-way handshake completed"}
        return {"status": "inconsistent", "note": "connect ok but no SYN-ACK captured"}
    if outcome == "reset":
        if flow["saw_synack"] and flow["saw_rst"]:
            return {"status": "confirmed",
                    "note": "handshake completed, then RST: connection aborted mid-stream"}
        return {"status": "inconsistent", "note": "app saw reset but no RST after a handshake"}
    return {"status": "n/a", "note": ""}