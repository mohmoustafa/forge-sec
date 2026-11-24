"""File discovery + language detection."""
from __future__ import annotations

import os
from pathlib import Path

from ..config import Config

LANG_BY_EXT = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".cs": "csharp",
    ".php": "php",
    ".sql": "sql",
    ".env": "envfile",
    ".yml": "yaml", ".yaml": "yaml",
    ".json": "json", ".xml": "xml", ".config": "xml",
    ".tf": "terraform",
    ".blade.php": "php",
    ".prisma": "prisma",
}

# generic rules also run on every text file
GENERIC = {"envfile", "yaml", "json", "xml", "terraform", "prisma"}


def detect_language(path: Path) -> str | None:
    name = path.name.lower()
    if name.endswith(".blade.php"):
        return "php"
    if name == ".env" or name.startswith(".env."):
        return "envfile"
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        return "dockerfile"
    if name.startswith("docker-compose") or name in ("compose.yml", "compose.yaml"):
        return "compose"
    if name.startswith("nginx") and name.endswith(".conf"):
        return "nginx"
    if name.startswith("appsettings") and name.endswith(".json"):
        return "appsettings"
    if name.endswith(".vue"):
        return "vue"
    ext = path.suffix.lower()
    return LANG_BY_EXT.get(ext)


def walk(cfg: Config) -> list[tuple[Path, str]]:
    out = []
    for dirpath, dirnames, filenames in os.walk(cfg.root):
        # prune excluded dirs early
        d = Path(dirpath)
        dirnames[:] = [dn for dn in dirnames if not cfg.excluded(
            str((d / dn).relative_to(cfg.root)).replace("\\", "/") + "/x")]
        for fn in filenames:
            p = d / fn
            try:
                relp = str(p.relative_to(cfg.root)).replace("\\", "/")
            except ValueError:
                continue
            if cfg.excluded(relp):
                continue
            lang = detect_language(p)
            if lang is None:
                continue
            try:
                if p.stat().st_size > cfg.max_file_kb * 1024:
                    continue
            except OSError:
                continue
            out.append((p, lang))
    return out
