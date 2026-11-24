"""Git history secrets scan: secrets deleted today still live in old commits."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .engine.rules import Rule, load_builtin
from .models import Finding, Severity

_COMMIT_RE = re.compile(r"^commit ([0-9a-f]{7,40})", re.M)


def _secret_rules() -> list[Rule]:
    return [r for r in load_builtin() if "secrets" in r.tags]


def scan_history(root: Path, max_commits: int = 500) -> list[Finding]:
    try:
        proc = subprocess.run(
            ["git", "log", "-p", "--all", f"-n{max_commits}", "--no-color",
             "--diff-filter=AM"],
            cwd=root, capture_output=True, text=True,
            errors="replace", timeout=600)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0 or not proc.stdout:
        return []

    rules = _secret_rules()
    findings: list[Finding] = []
    commit = "unknown"
    fname = "?"
    for line in proc.stdout.splitlines():
        m = _COMMIT_RE.match(line)
        if m:
            commit = m.group(1)[:8]
            fname = "?"
            continue
        if line.startswith("+++ b/"):
            fname = line[6:]
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        content = line[1:]
        for rule in rules:
            if rule.type == "file" or not rule._re:
                continue
            if rule._re.search(content):
                findings.append(Finding(
                    rule_id=rule.id, title=f"{rule.title} (in git history)",
                    severity=Severity.parse(rule.severity),
                    confidence=rule.confidence,
                    file=f"git:{commit}:{fname}", line=0,
                    message=f"{rule.message} Found in commit {commit}.",
                    snippet="[redacted]", cwe=rule.cwe, owasp=rule.owasp,
                    remediation=f"{rule.remediation} Rotate the credential AND purge history.",
                    engine="git-history", tags=rule.tags + ["history"]))
                break   # one rule per added line is enough
    # dedupe: same rule+file may appear in many commits -> keep first (oldest listed last wins anyway)
    seen, out = set(), []
    for f in findings:
        key = (f.rule_id, f.file.split(":", 2)[-1])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def scan_unreachable(root: Path, max_blobs: int = 2000) -> list[Finding]:
    """--deep: scan unreachable objects (deleted/amended-away blobs) via git fsck."""
    try:
        proc = subprocess.run(
            ["git", "fsck", "--unreachable", "--no-reflogs"],
            cwd=root, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    rules = _secret_rules()
    findings: list[Finding] = []
    blobs = [ln.split()[-1] for ln in proc.stdout.splitlines()
             if ln.startswith("unreachable blob")]
    for sha in blobs[:max_blobs]:
        try:
            blob = subprocess.run(["git", "cat-file", "-p", sha], cwd=root,
                                  capture_output=True, text=True,
                                  errors="replace", timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if blob.returncode != 0:
            continue
        for line in blob.stdout.splitlines():
            for rule in rules:
                if rule.type == "file" or not rule._re:
                    continue
                if rule._re.search(line):
                    findings.append(Finding(
                        rule_id=rule.id,
                        title=f"{rule.title} (unreachable object)",
                        severity=Severity.parse(rule.severity),
                        confidence=rule.confidence,
                        file=f"git-unreachable:{sha[:8]}", line=0,
                        message=f"{rule.message} Still recoverable from git object store.",
                        snippet="[redacted]", cwe=rule.cwe, owasp=rule.owasp,
                        remediation=f"{rule.remediation} Rotate; the object persists until gc/prune.",
                        engine="git-history", tags=rule.tags + ["history", "deep"]))
                    break
    seen, out = set(), []
    for f in findings:
        if (f.rule_id, f.file) not in seen:
            seen.add((f.rule_id, f.file))
            out.append(f)
    return out
