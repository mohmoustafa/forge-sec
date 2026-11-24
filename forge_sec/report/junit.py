"""JUnit XML (for CI dashboards) + Markdown PR summary."""
from __future__ import annotations

import html
from xml.etree.ElementTree import Element, SubElement, tostring

from ..models import Finding, Severity


def write_junit(findings: list[Finding], path, fail_on: str = "HIGH") -> None:
    th = Severity.parse(fail_on)
    ts = Element("testsuite", name="forge-sec",
                 tests=str(len(findings)),
                 failures=str(sum(1 for f in findings if f.severity >= th)))
    for f in findings:
        tc = SubElement(ts, "testcase",
                        classname=f"{f.file}",
                        name=f"{f.rule_id} {f.title} (line {f.line})")
        if f.severity >= th:
            fail = SubElement(tc, "failure",
                              type=f.severity.name,
                              message=f"{f.file}:{f.line} {f.message}")
            fail.text = f"{f.snippet}\n\nRemediation: {f.remediation}"
    path.write_bytes(b'<?xml version="1.0" encoding="utf-8"?>\n' + tostring(ts))


def write_markdown(findings: list[Finding], path, fail_on: str = "HIGH") -> None:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.name] = counts.get(f.severity.name, 0) + 1
    lines = ["## forge-sec report", ""]
    lines.append("| CRITICAL | HIGH | MEDIUM | LOW | INFO | total |")
    lines.append("|---|---|---|---|---|---|")
    lines.append("| " + " | ".join(
        str(counts.get(s, 0)) for s in
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]) + f" | {len(findings)} |")
    lines.append("")
    top = [f for f in findings if f.severity >= Severity.HIGH][:30]
    if top:
        lines += ["### Top findings", "",
                  "| severity | rule | location | issue |", "|---|---|---|---|"]
        for f in top:
            lines.append(
                f"| {f.severity.name} | {f.rule_id} | `{f.file}:{f.line}` | "
                + html.escape(f.title).replace("|", "\\|") + " |")
    else:
        lines.append("No HIGH+ findings.")
    path.write_text("\n".join(lines), encoding="utf-8")
