"""Unified finding model shared by every engine adapter."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from pathlib import Path


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, v: str | int) -> "Severity":
        if isinstance(v, int):
            return Severity(v)
        return cls[v.strip().upper()]

    @property
    def label(self) -> str:
        return self.name


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: str            # high | medium | low
    file: str                  # path relative to scan root
    line: int
    message: str
    snippet: str = ""
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    remediation: str = ""
    fix_example: str = ""
    references: list[str] = field(default_factory=list)
    engine: str = "builtin"    # builtin | bandit | semgrep | gitleaks | trivy | sca
    tags: list[str] = field(default_factory=list)
    language: str = ""
    col: int = 0
    end_line: int = 0
    kev: bool = False          # in CISA Known Exploited Vulnerabilities
    epss: float | None = None  # exploit probability 0..1
    cvss: float | None = None

    @property
    def fingerprint(self) -> str:
        """Stable id for dedup + baselines: rule + file + line + normalised snippet."""
        norm = " ".join(self.snippet.split())[:120]
        raw = f"{self.rule_id}|{self.file}|{self.line}|{norm}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def dedup_key(self) -> tuple:
        return (self.rule_id, self.file, self.line)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["fingerprint"] = self.fingerprint
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        d.pop("fingerprint", None)
        d["severity"] = Severity.parse(d["severity"])
        return cls(**d)


def dedup(findings: list[Finding]) -> list[Finding]:
    """Keep highest-confidence/severity per (rule,file,line)."""
    conf_rank = {"high": 3, "medium": 2, "low": 1}
    best: dict[tuple, Finding] = {}
    for f in findings:
        k = f.dedup_key()
        cur = best.get(k)
        if cur is None or (
            conf_rank.get(f.confidence, 0), f.severity
        ) > (conf_rank.get(cur.confidence, 0), cur.severity):
            best[k] = f
    return sorted(best.values(), key=lambda f: (-f.severity, f.file, f.line))


def rel(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(p)
