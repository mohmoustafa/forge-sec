"""Concrete adapters: bandit, semgrep, gitleaks, trivy. All auto-detected."""
from __future__ import annotations

import json
from pathlib import Path

from ...models import Finding, Severity, rel
from .base import Adapter, docker_available, exec_cmd, have

_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "MODERATE": Severity.MEDIUM,
    "LOW": Severity.LOW, "INFO": Severity.INFO,
    "WARNING": Severity.MEDIUM, "ERROR": Severity.HIGH,
}


def _sev(v: str, default=Severity.MEDIUM) -> Severity:
    return _SEV_MAP.get(str(v).upper(), default)


class BanditAdapter(Adapter):
    name = "bandit"

    def available(self) -> bool:
        if have("bandit"):
            return True
        try:
            import bandit  # noqa
            return True
        except ImportError:
            return False

    def run(self, root: Path) -> list[Finding]:
        if have("bandit"):
            cmd = ["bandit", "-r", ".", "-f", "json", "-q"]
        else:
            cmd = ["python", "-m", "bandit", "-r", ".", "-f", "json", "-q"]
        _, out = exec_cmd(cmd, root)
        try:
            data = json.loads(out)
        except Exception:
            return []
        findings = []
        for r in data.get("results", []):
            findings.append(Finding(
                rule_id=f"BANDIT-{r.get('test_id', '?')}",
                title=r.get("test_name", "bandit finding"),
                severity=_sev(r.get("issue_severity")),
                confidence=str(r.get("issue_confidence", "medium")).lower(),
                file=rel(Path(r.get("filename", "")), root),
                line=r.get("line_number", 1),
                message=r.get("issue_text", ""),
                snippet=(r.get("code") or "")[:400],
                cwe=[f"CWE-{r['issue_cwe']['id']}"] if r.get("issue_cwe") else [],
                engine="bandit", tags=["python"], language="python"))
        return findings


class SemgrepAdapter(Adapter):
    name = "semgrep"

    def available(self) -> bool:
        return bool(have("semgrep")) or docker_available()

    def _cmd(self) -> list[str]:
        if have("semgrep"):
            return ["semgrep", "scan", "--config", "p/owasp-top-ten",
                    "--config", "p/security-audit", "--json", "--quiet", "."]
        return ["docker", "run", "--rm", "-v", f"{Path.cwd()}:/src",
                "returntocorp/semgrep", "semgrep", "scan",
                "--config", "p/owasp-top-ten", "--config", "p/security-audit",
                "--json", "--quiet", "/src"]

    def run(self, root: Path) -> list[Finding]:
        _, out = exec_cmd(self._cmd(), root, timeout=900)
        try:
            data = json.loads(out)
        except Exception:
            return []
        findings = []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            cwes = meta.get("cwe") or []
            if isinstance(cwes, str):
                cwes = [cwes]
            findings.append(Finding(
                rule_id="SEMGREP-" + r.get("check_id", "?").split(".")[-1],
                title=r.get("check_id", "semgrep finding").split(".")[-1],
                severity=_sev(extra.get("severity")),
                confidence=str(meta.get("confidence", "medium")).lower(),
                file=rel(Path(r.get("path", "")), root),
                line=(r.get("start") or {}).get("line", 1),
                message=(extra.get("message") or "")[:400],
                snippet=(extra.get("lines") or "")[:400],
                cwe=cwes if isinstance(cwes, list) else [],
                owasp=[o for o in (meta.get("owasp") or [])] if isinstance(meta.get("owasp"), (list, str)) else [],
                remediation=meta.get("fix", "") or "",
                engine="semgrep",
                tags=list(meta.get("technology", []) or []),
                language=(extra.get("metadata", {}) or {}).get("technology", [""])[0]
                if meta.get("technology") else ""))
        return findings


class GitleaksAdapter(Adapter):
    name = "gitleaks"

    def available(self) -> bool:
        return bool(have("gitleaks")) or docker_available()

    def _cmd(self, report: Path) -> list[str]:
        if have("gitleaks"):
            return ["gitleaks", "detect", "--source", ".", "--no-git",
                    "--report-format", "json", "--report-path", str(report), "--exit-code", "0"]
        return ["docker", "run", "--rm", "-v", f"{Path.cwd()}:/src",
                "zricethezav/gitleaks", "detect", "--source", "/src", "--no-git",
                "--report-format", "json", "--report-path", "/src/.gitleaks.json", "--exit-code", "0"]

    def run(self, root: Path) -> list[Finding]:
        report = root / ".forge-sec-gitleaks.json"
        exec_cmd(self._cmd(report), root)
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except Exception:
            return []
        finally:
            report.unlink(missing_ok=True)
        return [Finding(
            rule_id=f"GITLEAKS-{r.get('RuleID', 'secret')}",
            title=f"Secret detected: {r.get('RuleID', '?')}",
            severity=Severity.CRITICAL, confidence="high",
            file=rel(Path(r.get("File", "")), root),
            line=r.get("StartLine", 1),
            message="Potential secret/credential committed to the repository.",
            snippet="[redacted by forge-sec]",
            remediation="Revoke and rotate; move to a secrets manager; purge git history.",
            cwe=["CWE-798"], owasp=["A07:2021"],
            engine="gitleaks", tags=["secrets"])
            for r in (data if isinstance(data, list) else [])]


class TrivyAdapter(Adapter):
    name = "trivy"

    def available(self) -> bool:
        return bool(have("trivy")) or docker_available()

    def _cmd(self) -> list[str]:
        base = (["trivy", "fs", "--scanners", "vuln,secret,misconfig",
                 "--format", "json", "."] if have("trivy")
                else ["docker", "run", "--rm", "-v", f"{Path.cwd()}:/src",
                      "aquasec/trivy", "fs", "--scanners", "vuln,secret,misconfig",
                      "--format", "json", "/src"])
        return base

    def run(self, root: Path) -> list[Finding]:
        _, out = exec_cmd(self._cmd(), root, timeout=900)
        try:
            data = json.loads(out)
        except Exception:
            return []
        findings = []
        for res in data.get("Results", []) or []:
            target = res.get("Target", "")
            for v in res.get("Vulnerabilities", []) or []:
                findings.append(Finding(
                    rule_id=f"TRIVY-{v.get('VulnerabilityID', '?')}",
                    title=f"Vulnerable dependency: {v.get('PkgName', '?')}@{v.get('InstalledVersion', '?')}",
                    severity=_sev(v.get("Severity")), confidence="high",
                    file=rel(Path(target), root), line=1,
                    message=(v.get("Title") or v.get("Description") or "")[:300],
                    remediation=f"Upgrade to {v.get('FixedVersion', '?')}" if v.get("FixedVersion") else "See advisory.",
                    references=[v.get("PrimaryURL", "")], engine="trivy",
                    tags=["sca", "container"], cwe=v.get("CweIDs", []) or [],
                    cvss=(v.get("CVSS", {}).get("nvd", {}) or {}).get("V3Score")))
            for s in res.get("Secrets", []) or []:
                findings.append(Finding(
                    rule_id=f"TRIVY-SECRET-{s.get('RuleID', '?')}",
                    title=f"Secret: {s.get('Title', s.get('RuleID', '?'))}",
                    severity=Severity.CRITICAL, confidence="high",
                    file=rel(Path(target), root), line=s.get("StartLine", 1),
                    message="Secret found in filesystem.",
                    snippet="[redacted by forge-sec]",
                    remediation="Revoke, rotate, purge history.",
                    cwe=["CWE-798"], engine="trivy", tags=["secrets"]))
            for m in res.get("Misconfigurations", []) or []:
                findings.append(Finding(
                    rule_id=f"TRIVY-MISC-{m.get('ID', '?')}",
                    title=m.get("Title", "Misconfiguration"),
                    severity=_sev(m.get("Severity"), Severity.MEDIUM),
                    confidence="high", file=rel(Path(target), root),
                    line=(m.get("CauseMetadata", {}) or {}).get("StartLine", 1),
                    message=(m.get("Message") or m.get("Description") or "")[:300],
                    remediation=m.get("Resolution", ""),
                    engine="trivy", tags=["iac", "misconfig"]))
        return findings


ADAPTERS = [BanditAdapter, SemgrepAdapter, GitleaksAdapter, TrivyAdapter]


def available_adapters() -> list[Adapter]:
    out = []
    for cls in ADAPTERS:
        a = cls()
        try:
            if a.available():
                out.append(a)
        except Exception:
            pass
    return out
