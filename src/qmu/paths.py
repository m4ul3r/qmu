from __future__ import annotations

import os
import platform
import tempfile
from pathlib import Path


SKILL_NAME = "qmu"


def repo_root() -> Path:
    """Root of a *source checkout*: two levels above this file (src/qmu/ -> repo).

    Only meaningful when qmu runs from a git/source checkout. In an installed
    wheel this resolves to something like ``<venv>/lib/pythonX.Y/`` — NOT a qmu
    repo — so callers must never assume paths under it (e.g. ``skills/``) exist.
    Skill discovery goes through all_skill_source_dirs(), which validates each
    candidate location instead of trusting this path.
    """
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


def _candidate_skills_roots() -> list[Path]:
    """Candidate locations of the skills/ source tree, in priority order.

    1. <repo_root>/skills — a git/source checkout. This is the only location
       that exists today: the wheel built by uv_build does NOT bundle the
       top-level skills/ tree (the backend has no way to include files from
       outside src/qmu/ in the package, and its `data` setting would dump the
       skill dirs straight into sys.prefix). So `qmu skill install` from a
       plain `pip install qmu` wheel currently has nothing to install and the
       caller's "No skill sources found under skills/" error is accurate.
    2. <package dir>/skills (i.e. qmu/skills/ inside site-packages) — checked
       so that skills shipped *inside* the package (by a future packaging
       change, an sdist hook, or a downstream repackager) are found with no
       code changes here.
    """
    pkg_dir = Path(__file__).resolve().parent
    return [
        repo_root() / "skills",
        pkg_dir / "skills",
    ]


def _skill_dirs_under(skills_root: Path) -> list[Path]:
    """Return sorted skills_root/<name>/ dirs that contain a SKILL.md."""
    if not skills_root.is_dir():
        return []
    return sorted(
        d for d in skills_root.iterdir()
        if d.is_dir() and (d / "SKILL.md").is_file()
    )


def skill_source_dir() -> Path:
    """Source dir of the primary 'qmu' skill.

    Prefers the first candidate root that actually contains the skill; falls
    back to the historical source-checkout path (which may not exist — callers
    that need a guaranteed-valid dir should use all_skill_source_dirs()).
    """
    for root in _candidate_skills_roots():
        candidate = root / SKILL_NAME
        if (candidate / "SKILL.md").is_file():
            return candidate
    return repo_root() / "skills" / SKILL_NAME


def all_skill_source_dirs() -> list[Path]:
    """Return all skills/<name>/ dirs that contain a SKILL.md.

    Searches the source-checkout location first, then a packaged location
    (see _candidate_skills_roots()). Uses the first root that yields any
    valid skill dirs. Returns [] — never raises — when none are found.
    """
    for root in _candidate_skills_roots():
        dirs = _skill_dirs_under(root)
        if dirs:
            return dirs
    return []


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
