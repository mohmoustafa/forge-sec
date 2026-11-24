"""Incremental scan cache: sha1(file) -> findings. Unchanged files skip rescanning."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .models import Finding

CACHE_FILE = ".forge-sec/cache/filescan.json"


def _path(root: Path) -> Path:
    return root / CACHE_FILE


def sha(path: Path) -> str:
    h = hashlib.sha1()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def load(root: Path) -> dict:
    p = _path(root)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save(root: Path, cache: dict) -> None:
    p = _path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cache), encoding="utf-8")


def unchanged(cache: dict, relpath: str, digest: str) -> bool:
    e = cache.get(relpath)
    return bool(e) and e.get("sha") == digest


def get(cache: dict, relpath: str) -> list[Finding]:
    out = []
    for d in (cache.get(relpath) or {}).get("findings", []):
        try:
            out.append(Finding.from_dict(d))
        except Exception:
            pass
    return out


def put(cache: dict, relpath: str, digest: str, findings: list[Finding]) -> None:
    cache[relpath] = {"sha": digest,
                      "findings": [f.to_dict() for f in findings]}
