"""OSV.dev batch queries + CISA KEV + FIRST EPSS. All optional, offline-safe."""
from __future__ import annotations

import json
import time
from pathlib import Path

import requests

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def _cache_dir(root: Path) -> Path:
    d = root / ".forge-sec" / "cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def query_osv(deps: list[dict], offline: bool, root: Path, timeout=30) -> dict:
    """Return {dep_index: [vuln,...]}. Cache 24h."""
    if offline or not deps:
        return {}
    cache = _cache_dir(root) / "osv.json"
    key = json.dumps([(d["ecosystem"], d["name"], d["version"]) for d in deps], sort_keys=True)
    if cache.exists():
        try:
            blob = json.loads(cache.read_text())
            if blob.get("key") == key and time.time() - blob.get("ts", 0) < 86400:
                return {int(k): v for k, v in blob["results"].items()}
        except Exception:
            pass
    queries = [{"package": {"name": d["name"], "ecosystem": d["ecosystem"]},
                "version": d["version"]} for d in deps]
    results: dict[int, list] = {}
    try:
        for i in range(0, len(queries), 1000):  # OSV batch limit
            resp = requests.post(OSV_BATCH, json={"queries": queries[i:i + 1000]},
                                 timeout=timeout)
            resp.raise_for_status()
            stub_ids: dict[int, list[str]] = {}
            for j, r in enumerate(resp.json().get("results", [])):
                ids = [v["id"] for v in (r.get("vulns") or []) if v.get("id")]
                if ids:
                    stub_ids[i + j] = ids
        details = _fetch_details({vid for ids in stub_ids.values() for vid in ids},
                                timeout)
        for idx, ids in stub_ids.items():
            full = [details[vid] for vid in ids if vid in details]
            if full:
                results[idx] = full
        cache.write_text(json.dumps({"key": key, "ts": time.time(),
                                     "results": {str(k): v for k, v in results.items()}}))
    except requests.RequestException as e:
        print(f"[forge-sec] OSV query failed ({e}); continuing without SCA feed")
    return results


def _fetch_details(ids: set[str], timeout=30, cap=800) -> dict:
    """querybatch returns {id,modified} stubs; pull full vuln docs."""
    out = {}
    for n, vid in enumerate(sorted(ids)):
        if n >= cap:
            print(f"[forge-sec] detail fetch capped at {cap} vulns")
            break
        try:
            r = requests.get(f"https://api.osv.dev/v1/vulns/{vid}", timeout=timeout)
            if r.ok:
                out[vid] = r.json()
        except requests.RequestException:
            pass
    return out


def load_kev(offline: bool, root: Path) -> set[str]:
    if offline:
        return set()
    cache = _cache_dir(root) / "kev.json"
    if cache.exists() and time.time() - cache.stat().st_mtime < 86400:
        try:
            return set(json.loads(cache.read_text()))
        except Exception:
            pass
    try:
        data = requests.get(KEV_URL, timeout=30).json()
        ids = {v["cveID"] for v in data.get("vulnerabilities", [])}
        cache.write_text(json.dumps(sorted(ids)))
        return ids
    except Exception as e:
        print(f"[forge-sec] KEV fetch failed ({e})")
        return set()


def load_epss(cves: list[str], offline: bool, root: Path) -> dict[str, float]:
    if offline or not cves:
        return {}
    out: dict[str, float] = {}
    try:
        for i in range(0, len(cves), 100):
            chunk = ",".join(cves[i:i + 100])
            data = requests.get(EPSS_URL, params={"cve": chunk}, timeout=30).json()
            for row in data.get("data", []):
                out[row["cve"]] = float(row.get("epss", 0))
    except Exception:
        pass
    return out
