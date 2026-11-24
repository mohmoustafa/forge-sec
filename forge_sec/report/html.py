"""Self-contained interactive HTML report (no external assets)."""
from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime

from ..models import Finding, Severity

CSS = """
:root{--bg:#0f172a;--card:#1e293b;--line:#334155;--txt:#e2e8f0;--mut:#94a3b8;
--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#38bdf8;--info:#64748b;}
*{box-sizing:border-box;margin:0}
body{font:14px/1.55 ui-monospace,Consolas,'Segoe UI',sans-serif;background:var(--bg);color:var(--txt);padding:24px}
header{display:flex;align-items:baseline;gap:16px;flex-wrap:wrap;margin-bottom:20px}
h1{font-size:20px}
.mut{color:var(--mut)}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 18px;min-width:110px}
.card b{display:block;font-size:22px}
.bar{display:flex;height:8px;border-radius:4px;overflow:hidden;margin:8px 0 18px;background:var(--line)}
.bar span{display:block}
.controls{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.controls button{background:var(--card);color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:5px 12px;cursor:pointer}
.controls button.on{border-color:#60a5fa;background:#1d3a5f}
input[type=search]{background:var(--card);border:1px solid var(--line);border-radius:8px;color:var(--txt);padding:6px 12px;flex:1;min-width:220px}
.f{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:10px;padding:12px 16px;margin-bottom:10px}
.f.CRITICAL{border-left-color:var(--crit)}.f.HIGH{border-left-color:var(--high)}
.f.MEDIUM{border-left-color:var(--med)}.f.LOW{border-left-color:var(--low)}
.f h3{font-size:14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.badge{font-size:11px;padding:1px 8px;border-radius:20px;border:1px solid var(--line)}
.badge.CRITICAL{background:#3f1215;color:#fca5a5}.badge.HIGH{background:#431d07;color:#fdba74}
.badge.MEDIUM{background:#3f3006;color:#fde68a}.badge.LOW{background:#0c3049;color:#7dd3fc}
.badge.INFO{background:#243447;color:#cbd5e1}.badge.kev{background:#7f1d1d;color:#fecaca;font-weight:700}
.badge.new{background:#065f46;color:#a7f3d0;font-weight:700}
.loc{color:var(--mut);font-size:12px}
pre{background:#0b1220;border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin:8px 0;overflow-x:auto;font-size:12.5px}
.rem{color:#86efac;font-size:13px}
.meta{display:flex;gap:8px;flex-wrap:wrap;font-size:11px;color:var(--mut);margin-top:6px}
summary{cursor:pointer;color:#93c5fd;font-size:12px;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin:10px 0 20px}
th,td{border:1px solid var(--line);padding:5px 10px;text-align:left}
th{background:var(--card)}
"""

JS = """
function flt(){
 const q=document.getElementById('q').value.toLowerCase();
 const sev=[...document.querySelectorAll('.controls button.on')].map(b=>b.dataset.s);
 document.querySelectorAll('.f').forEach(e=>{
  const ok=(sev.length===0||sev.includes(e.dataset.s))&&e.innerText.toLowerCase().includes(q);
  e.style.display=ok?'':'none'});
}
document.querySelectorAll('.controls button').forEach(b=>b.onclick=()=>{b.classList.toggle('on');flt()});
document.getElementById('q').oninput=flt;
"""


def _badge(sev: Severity) -> str:
    return f'<span class="badge {sev.name}">{sev.name}</span>'


def render(findings: list[Finding], root: str, stats: dict,
           new_fps: set | None = None) -> str:
    sev_count = Counter(f.severity.name for f in findings)
    by_engine = Counter(f.engine for f in findings)
    by_lang = Counter(f.language or "-" for f in findings)
    kev_n = sum(1 for f in findings if f.kev)
    total = len(findings)

    cards = "".join(
        f'<div class="card"><b>{sev_count.get(s, 0)}</b>{s}</div>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    barw = {s: (sev_count.get(s, 0) / total * 100 if total else 0)
            for s in sev_count}
    bar = "".join(f'<span style="width:{barw[s]}%;background:var(--{c})"></span>'
                  for s, c in [("CRITICAL", "crit"), ("HIGH", "high"),
                               ("MEDIUM", "med"), ("LOW", "low"), ("INFO", "info")]
                  if barw.get(s))

    rows = []
    for f in findings:
        refs = " ".join(f'<a style="color:#93c5fd" href="{html.escape(r)}">ref</a>'
                        for r in f.references if r.startswith("http"))
        meta = [f"engine:{f.engine}", f"conf:{f.confidence}", f"fp:{f.fingerprint}"]
        meta += f.cwe + f.owasp + f.tags
        if f.kev:
            meta.append('<b style="color:#fca5a5">CISA-KEV exploited</b>')
        if f.epss is not None:
            meta.append(f"EPSS:{f.epss:.0%}")
        if f.cvss is not None:
            meta.append(f"CVSS:{f.cvss}")
        kev_b = '<span class="badge kev">KEV</span>' if f.kev else ""
        new_b = ('<span class="badge new">NEW</span>'
                 if new_fps and f.fingerprint in new_fps else "")
        details = ""
        if f.fix_example:
            details += f"<details><summary>suggested fix</summary><pre>{html.escape(f.fix_example)}</pre></details>"
        rows.append(f"""
<div class="f {f.severity.name}" data-s="{f.severity.name}">
 <h3>{_badge(f.severity)}{kev_b}{new_b} {html.escape(f.title)} <span class="loc">{html.escape(f.file)}:{f.line}</span></h3>
 <div>{html.escape(f.message)}</div>
 <pre>{html.escape(f.snippet)}</pre>
 <div class="rem">{html.escape(f.remediation)}</div>
 {details}
 <div class="meta">{' · '.join(html.escape(str(m)) for m in meta)} {refs}</div>
</div>""")

    eng_tbl = "".join(f"<tr><td>{e}</td><td>{n}</td></tr>" for e, n in by_engine.most_common())
    lang_tbl = "".join(f"<tr><td>{l}</td><td>{n}</td></tr>" for l, n in by_lang.most_common())
    sev_btns = "".join(
        f'<button data-s="{s}" class="on">{s} ({sev_count.get(s, 0)})</button>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    kev_line = (f'<div class="card" style="border-color:#7f1d1d"><b style="color:#fca5a5">{kev_n}</b>actively exploited (KEV)</div>'
                if kev_n else "")

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>forge-sec report - {html.escape(root)}</title><style>{CSS}</style></head><body>
<header><h1>forge-sec security report</h1>
<span class="mut">{html.escape(root)} · {datetime.now():%Y-%m-%d %H:%M} · {stats.get('files', 0)} files · {stats.get('rules', 0)} rules · engines: {', '.join(stats.get('engines', []))} · deterministic, no AI</span></header>
<div class="cards">{cards}{kev_line}<div class="card"><b>{total}</b>total</div></div>
<div class="bar">{bar}</div>
<div class="controls">{sev_btns}<input id="q" type="search" placeholder="filter: file / rule / cwe / text..."></div>
<div>{''.join(rows) or '<p style="color:#86efac">No findings. \u2705</p>'}</div>
<h2 style="margin-top:28px">Findings by engine</h2><table>{eng_tbl}</table>
<h2>Findings by language</h2><table>{lang_tbl}</table>
<p class="mut">Exit gate: fail on {stats.get('fail_on', 'HIGH')}+ -> {"<b style='color:#fca5a5'>FAIL</b>" if stats.get('gate_failed') else "<b style='color:#86efac'>PASS</b>"} · fingerprints stable across runs for baseline diffing.</p>
<script>{JS}</script></body></html>"""


def write(findings: list[Finding], path, root: str, stats: dict,
          new_fps: set | None = None) -> None:
    path.write_text(render(findings, root, stats, new_fps), encoding="utf-8")


def write_json(findings: list[Finding], path, stats: dict) -> None:
    path.write_text(json.dumps({"stats": stats,
                                "findings": [f.to_dict() for f in findings]},
                               indent=2), encoding="utf-8")
