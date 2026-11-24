"""Scan history in SQLite (.forge-sec/history.db) + trend reporting."""
from __future__ import annotations

import sqlite3
import time
from collections import Counter
from pathlib import Path

from .models import Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, critical INT, high INT, medium INT, low INT, info INT,
  total INT, kev INT, files INT);
"""


def _db(root: Path) -> sqlite3.Connection:
    d = root / ".forge-sec"
    d.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(d / "history.db")
    conn.executescript(_SCHEMA)
    return conn


def record(root: Path, findings: list[Finding], files: int) -> None:
    c = Counter(f.severity.name for f in findings)
    kev = sum(1 for f in findings if f.kev)
    conn = _db(root)
    conn.execute(
        "INSERT INTO scans(ts,critical,high,medium,low,info,total,kev,files)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        (time.time(), c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"],
         c["INFO"], len(findings), kev, files))
    conn.commit()
    conn.close()


def trend(root: Path, limit: int = 20) -> list[dict]:
    conn = _db(root)
    rows = conn.execute(
        "SELECT ts,critical,high,medium,low,info,total,kev,files"
        " FROM scans ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [{"ts": r[0], "critical": r[1], "high": r[2], "medium": r[3],
             "low": r[4], "info": r[5], "total": r[6], "kev": r[7],
             "files": r[8]} for r in reversed(rows)]


def sparkline(values: list[int]) -> str:
    bars = "._-:=+*#"           # ASCII-safe (cp1252 consoles can't print blocks)
    if not values:
        return ""
    mx = max(values) or 1
    return "".join(bars[min(7, round(v / mx * 7))] for v in values)
