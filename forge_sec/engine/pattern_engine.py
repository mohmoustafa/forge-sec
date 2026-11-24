"""Built-in deterministic engine: regex patterns + lightweight intra-file taint."""
from __future__ import annotations

import re
from pathlib import Path

from ..config import Config
from ..models import Finding, Severity, rel
from .rules import Rule

# chars that strip a variable name out of a taint-source capture
_VAR_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$.()\[\]-]*")

# inline suppression:  forge-sec-ignore  |  forge-sec-ignore PY-003 SEC-001
_IGNORE_RE = re.compile(r"forge-sec-ignore\b([^\n]*)")
_IGNORE_ALL = {"forge-sec-ignore-file"}

def _depth0_literals(pattern: str) -> list[list[str]]:
    """Split a regex into top-level alternation branches and return, per branch,
    the literal runs that sit OUTSIDE all groups — i.e. required for a match."""
    branches: list[list[str]] = [[]]
    cur: list[str] = []
    depth = 0
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            esc = pattern[i + 1]
            if esc in ".^$*+?{}[]|()<>-":        # literal escaped char
                if depth == 0:
                    cur.append(esc)
            else:                                # \w \d \s \b ... = wildcard, breaks run
                if depth == 0 and cur:
                    branches[-1].append("".join(cur))
                    cur = []
            i += 2
            continue
        if ch == "(":
            if depth == 0 and cur:
                branches[-1].append("".join(cur))
                cur = []
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "[":
            if depth == 0 and cur:
                branches[-1].append("".join(cur))
                cur = []
            # skip the char class
            i += 1
            while i < len(pattern) and pattern[i] != "]":
                if pattern[i] == "\\":
                    i += 1
                i += 1
        elif ch == "|" and depth == 0:
            if cur:
                branches[-1].append("".join(cur))
                cur = []
            branches.append([])
        elif ch in "*+?{}^$":
            if depth == 0 and cur:
                # quantifier/anchor may relax the tail char; keep run minus last char
                if len(cur) > 1:
                    branches[-1].append("".join(cur[:-1]))
                cur = []
        elif depth == 0:
            cur.append(ch)
        i += 1
    if cur:
        branches[-1].append("".join(cur))
    return branches


def _best(lits: list[str], min_len: int = 5) -> str:
    cands = [l for l in lits if len(l.strip()) >= min_len]
    return max(cands, key=len, default="")


_LITERAL_CACHE: dict[str, tuple] = {}


def _literal_for(rule: "Rule") -> tuple:
    """Returns ('all', lit) — lit required; or ('any', [lits]) — one branch lit enough.
    ('all','') means cannot prefilter."""
    cached = _LITERAL_CACHE.get(rule.id)
    if cached is None:
        candidates = [rule.pattern] if rule.type != "taint" else [rule.source, rule.sink]
        mode, val = "all", ""
        for pat in candidates:
            if not pat:
                continue
            branches = _depth0_literals(pat)
            if len(branches) == 1:
                lit = _best(branches[0])
                if lit:
                    mode, val = "all", lit
                    break
            else:
                lits = [_best(b) for b in branches]
                lits = [l for l in lits if l]
                if lits and len(lits) == len(branches):
                    mode, val = "any", lits
                    break
        cached = (mode, val)
        _LITERAL_CACHE[rule.id] = cached
    return cached


def _ignores(lines: list[str]) -> dict[int, set[str]]:
    """line index -> set of suppressed rule ids ('*' = all)."""
    out: dict[int, set[str]] = {}
    for i, line in enumerate(lines):
        m = _IGNORE_RE.search(line)
        if not m:
            continue
        tail = m.group(1).strip()
        ids = {t for t in re.split(r"[\s,]+", tail) if re.fullmatch(r"[A-Z]{2,4}-\d+|\*", t)}
        out.setdefault(i, set()).update(ids or {"*"})
    return out


def _suppressed(rule_id: str, line_no: int, ignores: dict[int, set[str]]) -> bool:
    for idx in (line_no - 1, line_no - 2):          # same line or line above
        ids = ignores.get(idx)
        if ids and ("*" in ids or rule_id in ids):
            return True
    return False


def _snippet(lines: list[str], idx: int, span: int = 1) -> str:
    lo = max(0, idx - 0)
    hi = min(len(lines), idx + span)
    return "\n".join(lines[lo:hi]).strip()[:400]


def _mk(rule: Rule, path: Path, cfg: Config, line_no: int,
        snippet: str, msg_extra: str = "", conf: str | None = None) -> Finding:
    sev = cfg.severity_overrides.get(rule.id, rule.severity)
    return Finding(
        rule_id=rule.id, title=rule.title,
        severity=Severity.parse(sev),
        confidence=conf or rule.confidence,
        file=rel(path, cfg.root), line=line_no,
        message=rule.message or rule.title,
        snippet=snippet, cwe=rule.cwe, owasp=rule.owasp,
        remediation=rule.remediation, fix_example=rule.fix_example,
        references=rule.references, engine="builtin",
        tags=rule.tags, language="",  # language filled by caller
    )


def _run_pattern(rule: Rule, path: Path, cfg: Config, text: str,
                 lines: list[str], lang: str) -> list[Finding]:
    out = []
    for m in rule._re.finditer(text):
        if rule._ctx:
            # context applies to the whole line the match sits in, not the match itself
            ls = text.rfind("\n", 0, m.start()) + 1
            le = text.find("\n", m.end())
            line_text = text[ls:le if le != -1 else len(text)]
            if not rule._ctx.search(line_text):
                continue
        line_no = text.count("\n", 0, m.start()) + 1
        f = _mk(rule, path, cfg, line_no, _snippet(lines, line_no - 1))
        f.language = lang
        out.append(f)
    return out


def _run_file(rule: Rule, path: Path, cfg: Config, text: str,
              lines: list[str], lang: str) -> list[Finding]:
    matched = bool(rule._re and rule._re.search(text))
    if rule.absent:
        if not matched:
            f = _mk(rule, path, cfg, 1, lines[0][:200] if lines else "")
            f.language = lang
            return [f]
        return []
    if matched:
        return _run_pattern(rule, path, cfg, text, lines, lang)
    return []


# cross-file registry: function names that carry a parameter into a sink
_CROSS_RE: re.Pattern | None = None
_CROSS_LANG: dict[str, str] = {}


def set_cross_registry(names: dict[str, str]) -> None:
    global _CROSS_RE, _CROSS_LANG
    _CROSS_LANG = names or {}
    if names:
        alt = "|".join(re.escape(n) for n in names)
        _CROSS_RE = re.compile(r"\b(" + alt + r")\s*\(")
    else:
        _CROSS_RE = None


def _run_taint(rule: Rule, path: Path, cfg: Config,
               lines: list[str], lang: str) -> list[Finding]:
    """var = <source>   ...within `window` lines...   <sink>(... var ...)"""
    out = []
    tainted: list[tuple[str, int]] = []          # (varname, assign line idx)
    for i, line in enumerate(lines):
        if rule._src:
            m = rule._src.search(line)
            if m:
                var = (m.groupdict().get("var") or m.group(1) or "").strip()
                for v in _VAR_RE.findall(var):
                    tainted.append((v, i))
        sink_hit = bool(rule._snk and rule._snk.search(line))
        cross_fn = None
        if not sink_hit and _CROSS_RE:
            cm = _CROSS_RE.search(line)
            if cm and _CROSS_LANG.get(cm.group(1)) == lang:
                cross_fn = cm.group(1)
        if sink_hit or cross_fn:
            for var, ai in tainted:
                if i - ai > rule.window:
                    continue
                if var and re.search(r"(?<![\w$])" + re.escape(var) + r"(?![\w$])", line):
                    conf = "high" if i == ai else "medium"
                    extra = (f"tainted variable '{var}' (line {ai + 1})"
                             if sink_hit else
                             f"tainted '{var}' reaches sink via function '{cross_fn}'")
                    f = _mk(rule, path, cfg, i + 1,
                            _snippet(lines, i),
                            msg_extra=extra, conf=conf)
                    f.language = lang
                    f.tags = f.tags + (["cross-file"] if cross_fn else [])
                    out.append(f)
                    break
        # expire old
        tainted = [(v, ai) for v, ai in tainted if i - ai <= rule.window]
    return out


def _entropy_scan(path: Path, cfg: Config, lines: list[str], lang: str) -> list[Finding]:
    """High-entropy string literals that pattern rules can't recognise."""
    out = []
    for i, line in enumerate(lines[:2000]):
        for m in _STRING_RE.finditer(line):
            s = m.group(1) or m.group(2)
            if not s or len(s) < 20 or len(s) > 200:
                continue
            if " " in s or s.startswith(("http", "/", "./", "COM1", "SHA-", "-----")):
                continue
            if not re.fullmatch(r"[A-Za-z0-9+/=_@.#~:;!$%&*?-]+", s):
                continue
            ent = _entropy(s)
            if ent < 4.5:
                continue
            if _WORDY.search(s):
                continue
            f = Finding(
                rule_id="SEC-ENT-001",
                title="High-entropy literal (possible secret)",
                severity=Severity.MEDIUM, confidence="low",
                file=rel(path, cfg.root), line=i + 1,
                message=f"String literal with Shannon entropy {ent:.2f} bits/char "
                        "looks like generated key material.",
                snippet="[redacted]",
                cwe=["CWE-798"], owasp=["A07:2021"],
                remediation="If this is a real credential: rotate it and move to a "
                            "secrets manager. If not, add 'forge-sec-ignore SEC-ENT-001'.",
                engine="builtin", tags=["secrets", "entropy"], language=lang)
            out.append(f)
            if len(out) >= 10:
                return out
    return out


def _entropy(s: str) -> float:
    from math import log2
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


_STRING_RE = re.compile(r"\"([^\"]{16,200})\"|'([^']{16,200})'")
_WORDY = re.compile(r"(?i)(error|message|exception|select|insert|update|delete|"
                    r"function|module|package|version|default|setting|example|sample)")


def run(path: Path, lang: str, rules: list[Rule], cfg: Config) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.split("\n")
    head = "\n".join(lines[:15])
    if "forge-sec-ignore-file" in head:
        return []
    ignores = _ignores(lines)
    text_l = text.lower()
    out: list[Finding] = []
    for rule in rules:
        if rule.id in cfg.disabled_rules:
            continue
        if rule.languages and lang not in rule.languages:
            continue
        if not rule.absent:   # absent-rules fire on missing content; never prefilter
            mode, lit = _literal_for(rule)
            if mode == "all" and lit and lit.lower() not in text_l:
                continue
            if mode == "any" and lit and not any(l.lower() in text_l for l in lit):
                continue
        if rule.type == "taint":
            out.extend(_run_taint(rule, path, cfg, lines, lang))
        elif rule.type == "file":
            out.extend(_run_file(rule, path, cfg, text, lines, lang))
        else:
            out.extend(_run_pattern(rule, path, cfg, text, lines, lang))
    if lang in ("python", "javascript", "typescript", "csharp", "php") \
            and "SEC-ENT-001" not in cfg.disabled_rules:
        out.extend(_entropy_scan(path, cfg, lines, lang))
    if ignores:
        out = [f for f in out if not _suppressed(f.rule_id, f.line, ignores)]
    return out


# ---------- parallel scanning (ProcessPool; rules compiled once per process) ----------

_RULES_G: list[Rule] = []
_CFG_G: dict = {}


def init_worker(rule_dicts: list[dict], cfg_payload: dict) -> None:
    global _RULES_G, _CFG_G
    _RULES_G = [Rule.from_dict(d) for d in rule_dicts]
    _CFG_G = cfg_payload
    set_cross_registry(cfg_payload.get("cross", {}))


def scan_one(job: tuple[str, str]) -> list[dict]:
    """Worker: scan one file. Returns serialized findings (pickle-safe)."""
    path = Path(job[0])
    cfg = Config(root=Path(_CFG_G["root"]))
    cfg.severity_overrides = _CFG_G["severity_overrides"]
    cfg.disabled_rules = _CFG_G["disabled_rules"]
    return [f.to_dict() for f in run(path, job[1], _RULES_G, cfg)]


def run_parallel(files: list[tuple[Path, str]], rules: list[Rule],
                 cfg: Config, workers: int) -> list[Finding]:
    from concurrent.futures import ProcessPoolExecutor

    rule_dicts = [r.to_dict() for r in rules]
    payload = {"root": str(cfg.root),
               "severity_overrides": cfg.severity_overrides,
               "disabled_rules": cfg.disabled_rules}
    payload["cross"] = getattr(cfg, "_cross", {})
    jobs = [(str(p), lang) for p, lang in files]
    out: list[Finding] = []
    with ProcessPoolExecutor(
            max_workers=workers,
            initializer=init_worker,
            initargs=(rule_dicts, payload)) as ex:
        for dicts in ex.map(scan_one, jobs, chunksize=16):
            for d in dicts:
                try:
                    out.append(Finding.from_dict(d))
                except Exception:
                    pass
    return out
