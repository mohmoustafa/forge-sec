"""Dependency manifest parsing -> (ecosystem, name, version) tuples."""
from __future__ import annotations

import json
import re
from pathlib import Path

# OSV ecosystem names
ECO_PY = "PyPI"
ECO_NPM = "npm"
ECO_PHP = "Packagist"
ECO_NUGET = "NuGet"
ECO_MVN = "Maven"
ECO_GEM = "RubyGems"
ECO_GO = "Go"
ECO_CRG = "crates.io"

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9._-]+?)\s*(?:\[.*?\])?\s*==\s*([A-Za-z0-9._*+-]+)")


def _req(spec: str) -> tuple[str, str] | None:
    """requirements.txt line. Only pinned == gives an exact version; else None."""
    spec = spec.strip()
    if not spec or spec.startswith(("#", "-", "git+")):
        return None
    m = _REQ_RE.match(spec)
    if m:
        return (m.group(1).lower(), m.group(2))
    m = re.match(r"^\s*([A-Za-z0-9._-]+)\s*$", spec)
    return None  # unpinned: cannot map to a version deterministically


def _npm_lock(path: Path) -> list[tuple[str, str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    out = []
    for key, meta in (data.get("packages") or {}).items():
        if key.startswith("node_modules/") and meta.get("version"):
            out.append((key.rsplit("node_modules/", 1)[-1], meta["version"]))
    for name, meta in (data.get("dependencies") or {}).items():
        if meta.get("version"):
            out.append((name, meta["version"]))
    return out


def _composer_lock(path: Path) -> list[tuple[str, str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    out = []
    for section in ("packages", "packages-dev"):
        for p in data.get(section) or []:
            if p.get("name") and p.get("version"):
                out.append((p["name"], p["version"].lstrip("v")))
    return out


def _csproj(path: Path) -> list[tuple[str, str]]:
    out = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for m in re.finditer(r'<PackageReference[^>]*Include="([^"]+)"[^>]*Version="([^"]+)"', text):
        out.append((m.group(1), m.group(2)))
    for m in re.finditer(r'<PackageReference[^>]*Version="([^"]+)"[^>]*Include="([^"]+)"', text):
        out.append((m.group(2), m.group(1)))
    return out


def _pom(path: Path) -> list[tuple[str, str]]:
    """pom.xml <dependency><groupId>:<artifactId><version> (literals only)."""
    out = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for dep in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
        b = dep.group(1)
        g = re.search(r"<groupId>([^<]+)", b)
        a = re.search(r"<artifactId>([^<]+)", b)
        v = re.search(r"<version>([^<]+)", b)
        if g and a and v and "$" not in v.group(1):
            out.append((f"{g.group(1).strip()}:{a.group(1).strip()}",
                        v.group(1).strip()))
    return out


def _gemfile_lock(path: Path) -> list[tuple[str, str]]:
    out = []
    try:
        in_specs = False
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip() == "specs:":
                in_specs = True
                continue
            if in_specs:
                m = re.match(r"^\s{4}([A-Za-z0-9._-]+)\s\(([^)]+)\)", line)
                if m:
                    out.append((m.group(1), m.group(2).split()[0]))
    except OSError:
        pass
    return out


def _gomod(path: Path) -> list[tuple[str, str]]:
    out = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for m in re.finditer(r"^\s*([^\s/(]+(?:\.[^\s/(]+)+/\S+)\s+v(\S+)", text, re.M):
        out.append((m.group(1), m.group(2)))
    return out


def _cargo_lock(path: Path) -> list[tuple[str, str]]:
    out = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for pkg in re.finditer(r'\[\[package\]\]\s*name\s*=\s*"([^"]+)"\s*version\s*=\s*"([^"]+)"',
                           text):
        out.append((pkg.group(1), pkg.group(2)))
    return out


def _packages_lock(path: Path) -> list[tuple[str, str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    out = []
    for fw in (data.get("dependencies") or {}).values():
        for name, meta in fw.items():
            v = (meta.get("resolved") or "").lstrip("v")
            if v:
                out.append((name, v))
    return out


def parse(root: Path) -> list[dict]:
    """Return [{'ecosystem','name','version','manifest'}] entries."""
    deps: list[dict] = []

    def add(eco, name, ver, manifest):
        deps.append({"ecosystem": eco, "name": name, "version": ver,
                     "manifest": str(manifest.relative_to(root)).replace("\\", "/")})

    for p in root.rglob("*"):
        n = p.name.lower()
        rel = str(p.relative_to(root)).replace("\\", "/")
        if any(seg in rel for seg in ("node_modules/", "vendor/", ".git/", "venv/", ".venv/", "bin/", "obj/")):
            continue
        if n in ("requirements.txt", "requirements-prod.txt") or n.startswith("requirements") and n.endswith(".txt"):
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                r = _req(line)
                if r:
                    add(ECO_PY, r[0], r[1], p)
        elif n == "package-lock.json":
            for name, ver in _npm_lock(p):
                add(ECO_NPM, name, ver, p)
        elif n == "composer.lock":
            for name, ver in _composer_lock(p):
                add(ECO_PHP, name, ver, p)
        elif n.endswith(".csproj"):
            for name, ver in _csproj(p):
                add(ECO_NUGET, name, ver, p)
        elif n == "packages.lock.json":
            for name, ver in _packages_lock(p):
                add(ECO_NUGET, name, ver, p)
        elif n == "pom.xml":
            for name, ver in _pom(p):
                add(ECO_MVN, name, ver, p)
        elif n == "gemfile.lock":
            for name, ver in _gemfile_lock(p):
                add(ECO_GEM, name, ver, p)
        elif n == "go.mod":
            for name, ver in _gomod(p):
                add(ECO_GO, name, ver, p)
        elif n == "cargo.lock":
            for name, ver in _cargo_lock(p):
                add(ECO_CRG, name, ver, p)
        elif n == "pipfile.lock":
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                for sec in ("default", "develop"):
                    for name, meta in (data.get(sec) or {}).items():
                        v = str(meta.get("version", "")).lstrip("=")
                        if v:
                            add(ECO_PY, name.lower(), v, p)
            except Exception:
                pass
    return deps
