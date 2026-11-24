"""YAML rule loading + schema.

Rule types:
  pattern: regex match -> finding (optionally requires `context` regex nearby)
  taint:   source_regex assigns to var; sink_regex using var within `window` lines
  file:    regex over whole file content (for missing-header checks use `absent`)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    type: str = "pattern"            # pattern | taint | file
    languages: list[str] = field(default_factory=list)  # [] = all text files
    pattern: str = ""
    context: str = ""                # optional extra regex that must match same line/file
    absent: bool = False             # for type=file: fire when pattern NOT found
    source: str = ""                 # taint: regex capturing assigned variable
    sink: str = ""                   # taint: regex matching dangerous use
    window: int = 25
    message: str = ""
    remediation: str = ""
    fix_example: str = ""
    confidence: str = "medium"
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    flags: int = re.IGNORECASE | re.MULTILINE

    def compile(self) -> None:
        self._re = re.compile(self.pattern, self.flags) if self.pattern else None
        self._ctx = re.compile(self.context, self.flags) if self.context else None
        self._src = re.compile(self.source, self.flags) if self.source else None
        self._snk = re.compile(self.sink, self.flags) if self.sink else None

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "severity": self.severity,
                "type": self.type, "languages": self.languages,
                "pattern": self.pattern, "context": self.context,
                "absent": self.absent, "source": self.source, "sink": self.sink,
                "window": self.window, "message": self.message,
                "remediation": self.remediation, "fix_example": self.fix_example,
                "confidence": self.confidence, "cwe": self.cwe,
                "owasp": self.owasp, "references": self.references,
                "tags": self.tags}

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        r = cls(**d)
        r.compile()
        return r


def _rules_dir() -> Path:
    return Path(resources.files("forge_sec") / "rules_builtin")


def load_builtin() -> list[Rule]:
    rules: list[Rule] = []
    for f in sorted(_rules_dir().glob("*.yml")):
        rules.extend(load_file(f))
    return rules


def load_file(path: Path) -> list[Rule]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rules = []
    for r in data.get("rules", []):
        rule = Rule(**r)
        rule.compile()
        rules.append(rule)
    return rules


def load_custom(root: Path) -> list[Rule]:
    """Optional user rules: .forge-sec/rules/*.yml"""
    rules = []
    d = root / ".forge-sec" / "rules"
    if d.is_dir():
        for f in sorted(d.glob("*.yml")):
            rules.extend(load_file(f))
    return rules
