"""SARIF 2.1.0 output for CI/GitHub code scanning."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from ..models import Finding, Severity

_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error",
          Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}


def emit(findings: list[Finding], tool_version: str = "0.1.0") -> dict:
    rules, results = {}, []
    for f in findings:
        rules.setdefault(f.rule_id, {
            "id": f.rule_id, "name": f.title[:120],
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.message or f.title},
            "help": {"text": f.remediation or ""},
            "properties": {"confidence": f.confidence,
                           "cwe": f.cwe, "owasp": f.owasp},
        })
        results.append({
            "ruleId": f.rule_id, "level": _LEVEL[f.severity],
            "message": {"text": f.message or f.title},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": max(1, f.line),
                           "snippet": {"text": f.snippet[:500]}},
            }}],
            "partialFingerprints": {"forge-sec/v1": f.fingerprint},
            "properties": {"engine": f.engine, "confidence": f.confidence,
                           "kev": f.kev, "epss": f.epss, "cvss": f.cvss},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "forge-sec", "version": tool_version,
                "informationUri": "https://github.com/malomatia/forge-sec",
                "rules": list(rules.values())}},
            "results": results,
            "invocations": [{"executionSuccessful": True,
                             "endTimeUtc": datetime.now(timezone.utc).isoformat()}],
        }],
    }


def write(findings: list[Finding], path) -> None:
    path.write_text(json.dumps(emit(findings), indent=2), encoding="utf-8")
