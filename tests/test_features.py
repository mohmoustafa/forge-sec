"""Feature tests: cache, ignore comments, gitignore, history, IaC, markers."""
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge_sec import config, history, scancache
from forge_sec.engine import pattern_engine, walker
from forge_sec.engine.rules import load_builtin
from forge_sec.models import dedup

FIXTURE = Path(__file__).parent / "fixtures" / "vulnapp"


def scan(root=FIXTURE):
    cfg = config.load(root)
    rules = load_builtin()
    out = []
    for path, lang in walker.walk(cfg):
        out.extend(pattern_engine.run(path, lang, rules, cfg))
    return dedup(out)


def test_inline_ignore_suppresses():
    cfg = config.load(FIXTURE)
    rules = load_builtin()
    safe = FIXTURE / "src" / "safe.py"
    found = pattern_engine.run(safe, "python", rules, cfg)
    assert not any(f.rule_id == "PY-002" for f in found)


def test_gitignore_excludes(tmp_path):
    (tmp_path / ".gitignore").write_text("ignored_dir/\n*.skip.py\n")
    d = tmp_path / "ignored_dir"
    d.mkdir()
    (d / "evil.py").write_text("eval(request.data)")
    (tmp_path / "skip.skip.py").write_text("eval(request.data)")
    (tmp_path / "ok.py").write_text("eval(request.data)")  # should still be scanned
    cfg = config.load(tmp_path)
    files = walker.walk(cfg)
    names = [p.name for p, _ in files]
    assert "ok.py" in names and "evil.py" not in names and "skip.skip.py" not in names


def test_iac_rules_fire():
    ids = {f.rule_id for f in scan()}
    for rid in ["IAC-DK-001", "IAC-DK-002", "IAC-DK-003", "IAC-DK-004",
                "IAC-DC-001", "IAC-DC-002", "IAC-DC-003", "IAC-DC-004"]:
        assert rid in ids, f"{rid} did not fire"


def test_cache_roundtrip(tmp_path):
    (tmp_path / "a.py").write_text("import os\nos.system('x')\n")
    cfg = config.load(tmp_path)
    rules = load_builtin()
    files = walker.walk(cfg)
    cache = {}
    for p, lang in files:
        rp = p.name
        found = pattern_engine.run(p, lang, rules, cfg)
        scancache.put(cache, rp, scancache.sha(p), found)
    scancache.save(tmp_path, cache)
    loaded = scancache.load(tmp_path)
    assert scancache.unchanged(loaded, "a.py", scancache.sha(tmp_path / "a.py"))
    back = scancache.get(loaded, "a.py")
    assert any(f.rule_id == "PY-002" for f in back)


@pytest.mark.skipif(not shutil.which("git"), reason="git not installed")
def test_git_history_finds_deleted_secret(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo)
    subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=repo)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo)
    (repo / "s.txt").write_text("key=AKIAIOSFODNN7EXAMPLE\n")
    subprocess.run(["git", "add", "-A"], cwd=repo)
    subprocess.run(["git", "commit", "-qm", "add"], cwd=repo)
    (repo / "s.txt").unlink()
    subprocess.run(["git", "add", "-A"], cwd=repo)
    subprocess.run(["git", "commit", "-qm", "remove"], cwd=repo)
    found = history.scan_history(repo)
    assert any(f.rule_id == "SEC-002" for f in found)


def test_rule_markers_in_fixtures():
    """Every `# XX-NNN` / `// XX-NNN` marker in a fixture must produce that rule's finding in that file."""
    cfg = config.load(FIXTURE)
    rules = load_builtin()
    failures = []
    for path, lang in walker.walk(cfg):
        text = path.read_text(encoding="utf-8", errors="replace")
        markers = set(re.findall(r"(?:#|//|;|--)\s*([A-Z]{2,4}-\d{3})\b", text))
        if not markers:
            continue
        found = {f.rule_id for f in pattern_engine.run(path, lang, rules, cfg)}
        for m in markers - found:
            # markers may describe intended rules only; report misses
            failures.append(f"{path.name}:{m}")
    assert not failures, f"marker rules that did not fire: {failures}"
