from __future__ import annotations

import os
import platform
import tempfile
from pathlib import Path


SKILL_NAME = "qmu"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def claude_home() -> Path:
    env = os.environ.get("CLAUDE_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".claude"


def codex_home() -> Path:
    env = os.environ.get("CODEX_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".codex"


def cache_home() -> Path:
    env = os.environ.get("QMU_CACHE_DIR")
    if env:
        return Path(env).expanduser()

    system = platform.system()
    home = Path.home()
    if system == "Darwin":
        return home / "Library" / "Caches" / "qmu"
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "qmu"
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "qmu"
    return home / ".cache" / "qmu"


def instances_dir() -> Path:
    return cache_home() / "instances"


def instance_json_path(vm_id: str) -> Path:
    return instances_dir() / f"{vm_id}.json"


def qmp_socket_path(vm_id: str) -> Path:
    return instances_dir() / f"{vm_id}.qmp.sock"


def serial_log_path(vm_id: str) -> Path:
    return instances_dir() / f"{vm_id}.serial.log"


def spill_root() -> Path:
    root = Path(tempfile.gettempdir()) / "qmu-spills"
    root.mkdir(parents=True, exist_ok=True)
    return root


def claude_skills_dir() -> Path:
    return claude_home() / "skills"


def codex_skills_dir() -> Path:
    return codex_home() / "skills"


def skill_source_dir() -> Path:
    return repo_root() / "skills" / SKILL_NAME


def config_home() -> Path:
    env = os.environ.get("QMU_CONFIG_DIR")
    if env:
        return Path(env).expanduser()

    system = platform.system()
    home = Path.home()
    if system == "Darwin":
        return home / "Library" / "Application Support" / "qmu"
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "qmu"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "qmu"
    return home / ".config" / "qmu"


def global_config_path() -> Path:
    return config_home() / "config.toml"
