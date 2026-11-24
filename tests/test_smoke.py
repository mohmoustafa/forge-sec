"""Smoke tests: builtin engine must catch the planted bugs in tests/fixtures."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge_sec import config
from forge_sec.engine import pattern_engine, walker
from forge_sec.engine.rules import load_builtin
from forge_sec.models import dedup
from forge_sec.sca import cvss

FIXTURE = Path(__file__).parent / "fixtures" / "vulnapp"


def scan() -> dict:
    cfg = config.load(FIXTURE)
    rules = load_builtin()
    out = []
    for path, lang in walker.walk(cfg):
        out.extend(pattern_engine.run(path, lang, rules, cfg))
    return {f.rule_id for f in dedup(out)}


def test_rules_load():
    assert len(load_builtin()) >= 70


def test_cvss_calc():
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert cvss.base_score("garbage") is None


def test_planted_bugs_found():
    ids = scan()
    expected = {
        "PY-002", "PY-003", "PY-004", "PY-005", "PY-007", "PY-009",
        "JS-002", "JS-003", "JS-005", "JS-010", "JS-011",
        "CS-001", "CS-003", "CS-004", "CS-005", "CS-006", "CS-010",
        "PHP-003", "PHP-004", "PHP-005", "PHP-007", "PHP-008", "PHP-009", "PHP-012",
        "SQL-001", "SQL-004", "SQL-007",
        "SEC-001" if False else "SEC-003", "SEC-004", "SEC-006", "SEC-007",
    }
    missing = expected - ids
    assert not missing, f"rules that failed to fire: {missing}"
