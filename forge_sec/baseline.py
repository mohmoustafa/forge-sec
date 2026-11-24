"""Baseline diffing: save fingerprints, report only NEW findings later."""
from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


def _path(root: Path) -> Path:
    d = root / ".forge-sec"
    d.mkdir(parents=True, exist_ok=True)
    return d / "baseline.json"


def load(root: Path) -> set[str]:
    p = _path(root)
    if p.exists():
        try:
            return set(json.loads(p.read_text()))
        except Exception:
            return set()
    return set()


def save(root: Path, findings: list[Finding]) -> None:
    _path(root).write_text(json.dumps(
        sorted({f.fingerprint for f in findings}), indent=1))


def diff(root: Path, findings: list[Finding]) -> tuple[list[Finding], list[str]]:
    """Returns (new_findings, resolved_fingerprints)."""
    old = load(root)
    now = {f.fingerprint for f in findings}
    new = [f for f in findings if f.fingerprint not in old]
    resolved = sorted(old - now)
    return new, resolved
