"""External engine adapters. Each reports availability and yields Findings."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Adapter:
    name: str

    def available(self) -> bool:
        raise NotImplementedError

    def run(self, root: Path) -> list:
        raise NotImplementedError


def have(binary: str) -> str | None:
    return shutil.which(binary)


def exec_cmd(cmd: list[str], root: Path, timeout=600) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=root, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout + ("\n" + p.stderr if p.stderr else "")
    except (OSError, subprocess.TimeoutExpired) as e:
        return -1, str(e)


def docker_available() -> bool:
    if not have("docker"):
        return False
    rc, _ = exec_cmd(["docker", "info", "--format", "{{.ServerVersion}}"],
                     Path.cwd(), timeout=15)
    return rc == 0
