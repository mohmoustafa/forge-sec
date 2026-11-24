"""forge-sec CLI.

  forge-sec scan [path] [--format html|json|sarif|all] [--offline]
                 [--save-baseline] [--new-only] [--fail-on LEVEL]
  forge-sec deps [path] [--offline]          # dependency CVE check only
  forge-sec rules                            # list built-in rules
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import os

from . import __version__, config, history, models, scancache
from .baseline import diff as baseline_diff, save as baseline_save
from .engine import pattern_engine, walker
from .engine.external.engines import available_adapters
from .engine.rules import load_builtin, load_custom
from .models import rel
from .report import html as html_report, sarif as sarif_report
from .sca import findings as sca_findings, manifests, osv


def _gate_failed(findings: list[models.Finding], fail_on: str) -> bool:
    th = models.Severity.parse(fail_on)
    return any(f.severity >= th for f in findings)


_CONF_RANK = {"high": 3, "medium": 2, "low": 1}


def run_scan(root: Path, cfg: config.Config, args) -> tuple[list[models.Finding], dict]:
    rules = load_builtin() + load_custom(root)
    files = walker.walk(cfg)

    # cross-file registry: functions that pass params into sinks
    from .engine import crossfile
    registry = crossfile.build_registry(files)
    pattern_engine.set_cross_registry(registry)
    cfg._cross = registry        # picked up by parallel workers

    # ----- incremental cache: skip unchanged files -----
    cache = {} if args.no_cache else scancache.load(root)
    todo, findings, digests = [], [], {}
    n_cached = 0
    for p, lang in files:
        rp = rel(p, root)
        h = scancache.sha(p)
        digests[rp] = h
        if h and scancache.unchanged(cache, rp, h):
            findings.extend(scancache.get(cache, rp))
            n_cached += 1
        else:
            todo.append((p, lang, rp, h))

    # ----- builtin engine: parallel when worth it -----
    if args.workers > 1 and len(todo) > 8:
        fresh = pattern_engine.run_parallel(
            [(p, l) for p, l, _, _ in todo], rules, cfg, args.workers)
    else:
        fresh = []
        for p, lang, _, _ in todo:
            fresh.extend(pattern_engine.run(p, lang, rules, cfg))

    findings.extend(fresh)
    if not args.no_cache:
        by_file: dict[str, list] = {}
        for f in fresh:
            by_file.setdefault(f.file, []).append(f)
        for p, lang, rp, h in todo:
            if h:
                scancache.put(cache, rp, h, by_file.get(rp, []))
        # drop cache entries for deleted files
        live = {rel(p, root) for p, _ in files}
        for k in list(cache):
            if k not in live:
                del cache[k]
        scancache.save(root, cache)

    engines = ["builtin"]
    if not args.no_external:
        for ad in available_adapters():
            try:
                res = ad.run(root)
                if res:
                    findings.extend(res)
                engines.append(ad.name)
            except Exception as e:
                print(f"[forge-sec] {ad.name} failed: {e}")

    deps = manifests.parse(root)
    kev = osv.load_kev(cfg.offline, root)
    osv_res = osv.query_osv(deps, cfg.offline, root)
    cves = [a for vulns in osv_res.values() for v in vulns
            for a in ([v.get("id", "")] + v.get("aliases", [])) if a.startswith("CVE-")]
    epss = osv.load_epss(sorted(set(cves)), cfg.offline, root)
    sca = sca_findings.build(deps, osv_res, kev, epss)
    if sca:
        findings.extend(sca)
        engines.append("sca/osv")

    if getattr(args, "history", False):
        hist = history.scan_history(root)
        if getattr(args, "deep", False):
            hist += history.scan_unreachable(root)
        if hist:
            findings.extend(hist)
            engines.append("git-history")

    findings = models.dedup(findings)

    # ----- confidence filter -----
    conf_min = _CONF_RANK[getattr(args, "confidence", "low") or "low"]
    if conf_min > 1:
        findings = [f for f in findings
                    if _CONF_RANK.get(f.confidence, 0) >= conf_min]

    stats = {"files": len(files), "rules": len(rules), "engines": engines,
             "deps": len(deps), "fail_on": cfg.fail_on,
             "cached_files": n_cached, "scanned_files": len(todo)}
    return findings, stats


def cmd_scan(args) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}")
        return 2
    cfg = config.load(root)
    if args.offline:
        cfg.offline = True
    if args.fail_on:
        cfg.fail_on = args.fail_on

    findings, stats = run_scan(root, cfg, args)

    # trend history (always recorded, cheap)
    try:
        from . import trend as _trend
        _trend.record(root, findings, stats["files"])
    except Exception:
        pass

    resolved = []
    new_fps = None
    if args.new_only:
        new_set = {f.fingerprint for f in findings}
        findings, resolved = baseline_diff(root, findings)
        new_fps = {f.fingerprint for f in findings}
        print(f"[forge-sec] baseline: {len(findings)} new, {len(resolved)} resolved")
    if args.save_baseline:
        baseline_save(root, findings)
        print("[forge-sec] baseline saved")

    stats["gate_failed"] = _gate_failed(findings, cfg.fail_on)
    outdir = Path(args.outdir) if args.outdir else root / ".forge-sec" / "reports"
    outdir.mkdir(parents=True, exist_ok=True)

    fmts = ({args.format} if args.format != "all"
            else {"html", "json", "sarif", "junit", "markdown"})
    if "html" in fmts:
        p = outdir / "forge-sec-report.html"
        html_report.write(findings, p, str(root), stats, new_fps)
        print(f"report : {p}")
    if "json" in fmts:
        p = outdir / "forge-sec-report.json"
        html_report.write_json(findings, p, stats)
        print(f"report : {p}")
    if "sarif" in fmts:
        p = outdir / "forge-sec-report.sarif"
        sarif_report.write(findings, p)
        print(f"report : {p}")
    if "junit" in fmts:
        p = outdir / "forge-sec-report.junit.xml"
        from .report.junit import write_junit
        write_junit(findings, p, cfg.fail_on)
        print(f"report : {p}")
    if "markdown" in fmts or "md" in fmts:
        p = outdir / "forge-sec-report.md"
        from .report.junit import write_markdown
        write_markdown(findings, p, cfg.fail_on)
        print(f"report : {p}")

    sev = {s.name: sum(1 for f in findings if f.severity == s)
           for s in models.Severity}
    kev = sum(1 for f in findings if f.kev)
    print(f"files: {stats['files']} ({stats['cached_files']} cached, "
          f"{stats['scanned_files']} scanned)")
    print(f"\nfindings: {len(findings)}  "
          f"(crit {sev['CRITICAL']} high {sev['HIGH']} med {sev['MEDIUM']} "
          f"low {sev['LOW']} info {sev['INFO']})"
          + (f"  KEV {kev}" if kev else ""))
    print(f"gate [{cfg.fail_on}+]: {'FAIL' if stats['gate_failed'] else 'PASS'}")
    return 1 if stats["gate_failed"] else 0


def cmd_deps(args) -> int:
    root = Path(args.path).resolve()
    cfg = config.load(root)
    if args.offline:
        cfg.offline = True
    deps = manifests.parse(root)
    print(f"{len(deps)} pinned dependencies found")
    res = osv.query_osv(deps, cfg.offline, root)
    kev = osv.load_kev(cfg.offline, root)
    n = 0
    for idx, vulns in sorted(res.items()):
        d = deps[idx]
        for v in vulns:
            cve = next((a for a in [v.get("id")] + v.get("aliases", [])
                        if a.startswith("CVE-")), v.get("id"))
            flag = "  [KEV]" if cve in kev else ""
            print(f"  {d['ecosystem']:9} {d['name']}@{d['version']:20} {cve}{flag}")
            n += 1
    print(f"{n} advisories")
    return 1 if n else 0


def cmd_image(args) -> int:
    """Container image scan via trivy (binary or docker)."""
    from .engine.external.base import docker_available, exec_cmd, have
    image = args.image
    if have("trivy"):
        cmd = ["trivy", "image", "--scanners", "vuln,secret,misconfig",
               "--format", "json", image]
    elif docker_available():
        cmd = ["docker", "run", "--rm",
               "-v", "/var/run/docker.sock:/var/run/docker.sock",
               "aquasec/trivy", "image", "--scanners", "vuln,secret,misconfig",
               "--format", "json", image]
    else:
        print("trivy binary or running Docker daemon required for image scans")
        return 2
    import json as _json
    _, out = exec_cmd(cmd, Path.cwd(), timeout=1800)
    try:
        data = _json.loads(out)
    except Exception:
        print(out[:500])
        return 2
    findings = []
    for res in data.get("Results", []) or []:
        target = res.get("Target", image)
        for v in res.get("Vulnerabilities", []) or []:
            findings.append(models.Finding(
                rule_id=f"TRIVY-{v.get('VulnerabilityID', '?')}",
                title=f"{v.get('PkgName', '?')}@{v.get('InstalledVersion', '?')}",
                severity=models.Severity.parse(
                    str(v.get("Severity", "MEDIUM")).title()),
                confidence="high", file=f"image:{image}",
                line=1,
                message=(v.get("Title") or v.get("Description") or "")[:300],
                remediation=(f"Upgrade to {v.get('FixedVersion')}"
                             if v.get("FixedVersion") else "See advisory."),
                engine="trivy", tags=["image", "sca"],
                cvss=(v.get("CVSS", {}).get("nvd", {}) or {}).get("V3Score")))
        for s in res.get("Secrets", []) or []:
            findings.append(models.Finding(
                rule_id=f"TRIVY-SECRET-{s.get('RuleID', '?')}",
                title=f"Secret in image: {s.get('Title', '?')}",
                severity=models.Severity.CRITICAL, confidence="high",
                file=f"image:{image}", line=1,
                message="Secret baked into image layer.",
                remediation="Remove the layer, rotate the credential.",
                engine="trivy", tags=["secrets"]))
    sev = {s.name: sum(1 for f in findings if f.severity == s)
           for s in models.Severity}
    print(f"{image}: {len(findings)} findings "
          f"(crit {sev['CRITICAL']} high {sev['HIGH']} med {sev['MEDIUM']})")
    th = models.Severity.parse(args.fail_on)
    bad = [f for f in findings if f.severity >= th]
    for f in bad[:25]:
        print(f"  {f.severity.name:8} {f.rule_id:30} {f.title[:60]}")
    return 1 if bad else 0


def cmd_dbcheck(args) -> int:
    from . import dbcheck
    try:
        findings = dbcheck.check(args.dsn)
    except RuntimeError as e:
        print(f"dbcheck: {e}")
        return 2
    except Exception as e:
        print(f"dbcheck: connection failed: {e}")
        return 2
    for f in findings:
        print(f"{f.severity.name:8} {f.rule_id:8} {f.title}: {f.message[:100]}")
    print(f"{len(findings)} findings")
    th = models.Severity.parse(args.fail_on)
    return 1 if any(f.severity >= th for f in findings) else 0


def cmd_watch(args) -> int:
    """Poll the tree and re-scan on change; alerts only on NEW findings."""
    import time
    root = Path(args.path).resolve()
    cfg = config.load(root)
    interval = args.interval
    print(f"[forge-sec] watching {root} every {interval}s (Ctrl+C to stop)")
    print("[forge-sec] initial baseline scan...")
    ns = argparse.Namespace(**vars(args))
    ns.history = False
    findings, stats = run_scan(root, cfg, ns)
    baseline_save(root, findings)
    print(f"[forge-sec] baseline: {len(findings)} findings")
    try:
        while True:
            time.sleep(interval)
            findings, stats = run_scan(root, cfg, ns)
            new, resolved = baseline_diff(root, findings)
            baseline_save(root, findings)
            if new or resolved:
                print(f"[{time.strftime('%H:%M:%S')}] "
                      f"{len(new)} new, {len(resolved)} resolved")
                th = models.Severity.parse(cfg.fail_on)
                for f in new:
                    if f.severity >= th:
                        print(f"  NEW {f.severity.name:8} {f.file}:{f.line} {f.title}")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] clean ({len(findings)} known)")
    except KeyboardInterrupt:
        print("\n[forge-sec] watch stopped")
    return 0


def cmd_trend(args) -> int:
    from . import trend as _trend
    root = Path(args.path).resolve()
    rows = _trend.trend(root, args.limit)
    if not rows:
        print("no scan history yet - run `forge-sec scan` first")
        return 0
    print(f"{'time':16} {'crit':>5} {'high':>5} {'med':>5} {'low':>5} "
          f"{'total':>6} {'kev':>4}  trend")
    for r in rows:
        import datetime
        ts = datetime.datetime.fromtimestamp(r["ts"]).strftime("%m-%d %H:%M")
        print(f"{ts:16} {r['critical']:>5} {r['high']:>5} {r['medium']:>5} "
              f"{r['low']:>5} {r['total']:>6} {r['kev']:>4}")
    totals = [r["total"] for r in rows]
    print(f"\ntotal trend: {_trend.sparkline(totals)}")
    return 0


def cmd_rules(_args) -> int:
    rules = load_builtin()
    for r in rules:
        langs = ",".join(r.languages) if r.languages else "all"
        print(f"{r.id:12} {r.severity:8} {r.type:7} [{langs:20}] {r.title}")
    print(f"\n{len(rules)} rules")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="forge-sec",
                                 description="deterministic security scanner (no AI)")
    ap.add_argument("--version", action="version", version=f"forge-sec {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="full scan")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--format", choices=["html", "json", "sarif", "junit",
                                        "markdown", "md", "all"], default="all")
    p.add_argument("--outdir")
    p.add_argument("--offline", action="store_true")
    p.add_argument("--no-external", action="store_true",
                   help="skip bandit/semgrep/gitleaks/trivy even if installed")
    p.add_argument("--save-baseline", action="store_true")
    p.add_argument("--new-only", action="store_true",
                   help="only report findings not in the saved baseline")
    p.add_argument("--fail-on", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p.add_argument("--workers", type=int,
                   default=min(4, (os.cpu_count() or 2)),
                   help="parallel scan processes (1 = sequential)")
    p.add_argument("--no-cache", action="store_true",
                   help="ignore the incremental scan cache")
    p.add_argument("--history", action="store_true",
                   help="also scan git history for committed secrets")
    p.add_argument("--deep", action="store_true",
                   help="with --history: also scan unreachable git objects (fsck)")
    p.add_argument("--confidence", choices=["low", "medium", "high"],
                   default="low",
                   help="only show findings at this confidence or above")
    p.set_defaults(fn=cmd_scan)

    d = sub.add_parser("deps", help="dependency advisory check only")
    d.add_argument("path", nargs="?", default=".")
    d.add_argument("--offline", action="store_true")
    d.set_defaults(fn=cmd_deps)

    r = sub.add_parser("rules", help="list built-in rules")
    r.set_defaults(fn=cmd_rules)

    im = sub.add_parser("image", help="scan a container image via trivy")
    im.add_argument("image")
    im.add_argument("--fail-on", default="HIGH",
                    choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    im.set_defaults(fn=cmd_image)

    db = sub.add_parser("dbcheck", help="live Postgres RLS/role checks")
    db.add_argument("--dsn", required=True)
    db.add_argument("--fail-on", default="HIGH",
                    choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    db.set_defaults(fn=cmd_dbcheck)

    w = sub.add_parser("watch", help="poll the tree, alert on NEW findings")
    w.add_argument("path", nargs="?", default=".")
    w.add_argument("--interval", type=int, default=30)
    w.add_argument("--workers", type=int, default=min(4, (os.cpu_count() or 2)))
    w.add_argument("--no-cache", action="store_true")
    w.add_argument("--no-external", action="store_true")
    w.add_argument("--offline", action="store_true")
    w.set_defaults(fn=cmd_watch)

    tr = sub.add_parser("trend", help="scan history + severity trend (sqlite)")
    tr.add_argument("path", nargs="?", default=".")
    tr.add_argument("--limit", type=int, default=20)
    tr.set_defaults(fn=cmd_trend)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
