"""Light cross-file taint: functions that pass a parameter into a dangerous sink
are registered once, then call sites in OTHER files become findings when called
with request-derived data.

Covers the 80% case: `def render(data): ... execute(data)` in helpers.py, then
`render(req.query.x)` in api.py. Not full inter-procedural analysis.
"""
from __future__ import annotations

import re
from pathlib import Path

# function definitions per language -> name, [params]
_FUNC_RE = {
    "python": re.compile(
        r"^\s*def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)", re.M),
    "javascript": re.compile(
        r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)|"
        r"(?:const|let|var|export\s+const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>|"
        r"export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\))", re.M),
    "typescript": None,   # same regex as javascript, set below
    "php": re.compile(
        r"function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)", re.M),
    "csharp": re.compile(
        r"(?:public|private|protected|internal|static|async|sealed|new|virtual|override|\s)+"
        r"[\w<>\[\],.?]+\s+([A-Za-z_]\w*)\s*\(([^)]*)\)", re.M),
}
_FUNC_RE["typescript"] = _FUNC_RE["javascript"]

_BODY_LINES = 40          # how many lines after a def we scan for sinks

_SINK_HINTS = re.compile(
    r"(execute|executemany|cursor\.execute|\.query|\.raw|eval\(|exec\(|"
    r"Process\.Start|SqlCommand|FromSqlRaw|shell_exec|passthru|unserialize|"
    r"readFile|sendFile|open\(|file_get_contents|requests\.|axios\.|fetch\(|"
    r"HttpClient|pickle\.loads|yaml\.load|jwt\.decode)", re.I)


def _params(argstr: str) -> list[str]:
    out = []
    for a in argstr.split(","):
        a = a.strip()
        m = re.search(r"([A-Za-z_$][\w$]*)", a.replace("$", ""))
        if m:
            out.append(m.group(1))
    return out[:6]


def build_registry(files: list[tuple[Path, str]], max_funcs: int = 500) -> dict[str, str]:
    """name -> lang for functions that flow a parameter into a sink hint."""
    registry: dict[str, str] = {}
    for path, lang in files:
        rx = _FUNC_RE.get(lang)
        if not rx or len(registry) >= max_funcs:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in rx.finditer(text):
            name = next((g for g in m.groups()[::2] if g), None)
            argstr = next((g for g in m.groups()[1::2] if g is not None), "")
            if not name:
                continue
            params = _params(argstr)
            if not params:
                continue
            body_start = text.count("\n", 0, m.end())
            body = "\n".join(text.split("\n")[body_start:body_start + _BODY_LINES])
            # does a param reach a sink-ish call inside the body?
            for p in params:
                for line in body.split("\n"):
                    if _SINK_HINTS.search(line) and re.search(
                            r"(?<![\w$])" + re.escape(p) + r"(?![\w$])", line):
                        registry[name] = lang
                        break
                if name in registry:
                    break
    return registry


# names registry consulted by taint engine: call sites
def call_sink_re(names: list[str]) -> re.Pattern | None:
    if not names:
        return None
    alt = "|".join(re.escape(n) for n in names)
    return re.compile(r"\b(" + alt + r")\s*\(")
