"""Deterministic CVSS v3.x base-score calculator from a vector string.

Supports CVSS:3.0 and CVSS:3.1 vectors, e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'.
Returns the base score (0.0-10.0) or None if unparseable.
"""
from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}


def _roundup(x: float) -> float:
    return math.ceil(x * 10 - 1e-9) / 10.0


def base_score(vector: str) -> float | None:
    if not vector or "CVSS:3" not in vector:
        return None
    parts = {}
    for seg in vector.split("/")[1:]:
        if ":" in seg:
            k, v = seg.split(":", 1)
            parts[k] = v
    try:
        av = _AV[parts["AV"]]
        ac = _AC[parts["AC"]]
        ui = _UI[parts["UI"]]
        s = parts["S"]
        pr = (_PR_C if s == "C" else _PR_U)[parts["PR"]]
        c = _CIA[parts["C"]]
        i = _CIA[parts["I"]]
        a = _CIA[parts["A"]]
    except KeyError:
        return None
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if s == "C" \
        else 6.42 * iss
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + exploit), 10) if s == "C"
                    else min(impact + exploit, 10))
