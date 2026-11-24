"""Project-level config: .forge-sec.yml at scan root."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_EXCLUDES = [
    ".git/*", "node_modules/*", "vendor/*", "venv/*", ".venv/*",
    "dist/*", "build/*", "bin/*", "obj/*", "target/*",
    "*.min.js", "*.map", "*.lock", "package-lock.json",
    "composer.lock", "yarn.lock", "poetry.lock", "*.svg",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.woff*", "*.pdf",
    ".forge-sec/*",
    "migrations/*",  # many frameworks ship generated SQL; sql rules still scan *.sql
]


@dataclass
class Config:
    root: Path
    excludes: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    includes: list[str] = field(default_factory=list)   # if set, only these
    severity_overrides: dict[str, str] = field(default_factory=dict)
    disabled_rules: list[str] = field(default_factory=list)
    offline: bool = False          # skip OSV/KEV/EPSS calls
    fail_on: str = "HIGH"          # CI gate threshold
    max_file_kb: int = 1024

    def excluded(self, relpath: str) -> bool:
        rel = relpath.replace("\\", "/")
        if self.includes:
            if not any(fnmatch.fnmatch(rel, p) for p in self.includes):
                return True
        return any(fnmatch.fnmatch(rel, p) for p in self.excludes)


def _gitignore_patterns(root: Path) -> list[str]:
    """Fold .gitignore entries into fnmatch-style excludes (negations ignored)."""
    f = root / ".gitignore"
    if not f.exists():
        return []
    out = []
    for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "!")):
            continue
        line = line.lstrip("/").rstrip("/")
        out.append(line)
        if not line.endswith("*"):
            out.append(line + "/*")
    return out


def load(root: Path) -> Config:
    cfg = Config(root=root)
    f = root / ".forge-sec.yml"
    if f.exists():
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        cfg.excludes = data.get("excludes", cfg.excludes)
        cfg.includes = data.get("includes", [])
        cfg.severity_overrides = data.get("severity_overrides", {})
        cfg.disabled_rules = data.get("disabled_rules", [])
        cfg.offline = bool(data.get("offline", False))
        cfg.fail_on = data.get("fail_on", cfg.fail_on)
        cfg.max_file_kb = int(data.get("max_file_kb", cfg.max_file_kb))
    cfg.excludes = list(cfg.excludes) + _gitignore_patterns(root)
    return cfg
