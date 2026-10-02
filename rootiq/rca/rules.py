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
    return (f"{e['id']}: {e['phase']} to {e['host']}:{e['port']} -> "
            f"{e['outcome']} after {e['elapsed_ms']} ms")


def diagnose_with_evidence(group: list[dict], evidence: list[dict]) -> dict:
    """Prefer observed socket outcomes over error-message matching."""
    d = diagnose(group)
    ids = {f["test_id"] for f in group}
    socks = [e for e in evidence
             if e.get("type") == "socket" and e.get("test_id") in ids]
    if not socks:
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

    if refused:
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
    return d