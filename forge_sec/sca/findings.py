"""Turn OSV results into Findings with KEV/EPSS enrichment."""
from __future__ import annotations

from ..models import Finding, Severity
from . import cvss

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}


def _cvss_to_sev(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _severity(v: dict) -> tuple[Severity, float | None]:
    best_s, best_score = Severity.LOW, None
    for s in v.get("severity", []) or []:
        if s.get("type", "").startswith("CVSS"):
            val = s.get("score", "")
            try:
                score = float(val)
            except (TypeError, ValueError):
                score = cvss.base_score(str(val))  # vector string
            if score is not None:
                sev = _cvss_to_sev(score)
                if sev > best_s:
                    best_s, best_score = sev, score
    # GitHub's curated severity as fallback signal
    dbsev = (v.get("database_specific") or {}).get("severity")
    if dbsev and dbsev.upper() in _SEV_RANK:
        s = Severity(_SEV_RANK[dbsev.upper()])
        if s > best_s:
            best_s = s
    return best_s, best_score


def _aliases(v: dict) -> list[str]:
    return [v.get("id", "")] + [a for a in v.get("aliases", []) or []]


def build(deps: list[dict], osv_results: dict, kev: set[str],
          epss: dict[str, float]) -> list[Finding]:
    out: list[Finding] = []
    for idx, vulns in osv_results.items():
        dep = deps[idx]
        pkg = f'{dep["name"]}@{dep["version"]}'
        for v in vulns:
            vid = v.get("id", "?")
            aliases = _aliases(v)
            cve = next((a for a in aliases if a.startswith("CVE-")), None)
            sev, score = _severity(v)
            is_kev = bool(cve and cve in kev)
            epss_score = epss.get(cve) if cve else None
            if is_kev:
                sev = Severity.CRITICAL
            fixed = []
            for aff in v.get("affected", []) or []:
                for rng in aff.get("ranges", []) or []:
                    for ev in rng.get("events", []):
                        if "fixed" in ev:
                            fixed.append(ev["fixed"])
            summary = v.get("summary") or v.get("details", "")[:160] or vid
            rem = f"Upgrade {dep['name']} to {', '.join(dict.fromkeys(fixed))}" if fixed \
                else f"No fixed version listed; check {vid} advisory."
            f = Finding(
                rule_id=f"SCA-{vid}", title=f"Vulnerable dependency: {pkg}",
                severity=sev, confidence="high", file=dep["manifest"], line=1,
                message=f"{vid}: {summary}",
                remediation=rem,
                references=[f"https://osv.dev/vulnerability/{vid}"],
                engine="sca", tags=["sca", dep["ecosystem"], "kev" if is_kev else "advisory"],
                cwe=[], kev=is_kev, epss=epss_score, cvss=score,
            )
            out.append(f)
    return out
