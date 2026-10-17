from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from qmu import cli, paths
from qmu.commands import lifecycle, meta


@pytest.fixture
def install_env(tmp_path, monkeypatch):
    """Fake skill source tree plus a fake $HOME every install root resolves under."""
    source_root = tmp_path / "skills"
    names = ["qmu", "qmu-linux-kbuild"]
    sources = []
    for name in names:
        src = source_root / name
        src.mkdir(parents=True)
        (src / "SKILL.md").write_text(f"# {name}\n")
        sources.append(src)
    monkeypatch.setattr(meta, "all_skill_source_dirs", lambda: list(sources))

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for var in ("CLAUDE_HOME", "CODEX_HOME", "AGENTS_HOME", "PI_CODING_AGENT_DIR"):
        monkeypatch.delenv(var, raising=False)

    return SimpleNamespace(home=home, names=names, sources=sources)


def test_install_links_agents_root_when_agents_dir_exists(install_env, capsys):
    (install_env.home / ".agents").mkdir()

    rc = cli.main(["skill", "install"])
    capsys.readouterr()

    assert rc == 0
    for name, src in zip(install_env.names, install_env.sources):
        for root in (".agents", ".claude"):
            dst = install_env.home / root / "skills" / name
            assert dst.is_symlink()
            assert dst.resolve() == src.resolve()
    assert not (install_env.home / ".codex").exists()


def test_install_creates_agents_skills_dir_when_only_omp_agent_dir_exists(install_env, capsys):
    (install_env.home / ".omp" / "agent").mkdir(parents=True)

    rc = cli.main(["skill", "install"])
    capsys.readouterr()

    assert rc == 0
    for name in install_env.names:
        assert (install_env.home / ".agents" / "skills" / name).is_symlink()


def test_install_honors_explicit_agents_home_before_it_exists(install_env, tmp_path, monkeypatch, capsys):
    alt = tmp_path / "alt-agents"
    monkeypatch.setenv("AGENTS_HOME", str(alt))
    assert not alt.exists()

    rc = cli.main(["skill", "install"])
    capsys.readouterr()

    assert rc == 0
    for name in install_env.names:
        assert (alt / "skills" / name).is_symlink()


def test_install_skips_and_reports_agents_root_when_omp_absent(install_env, capsys):
    rc = cli.main(["skill", "install"])
    out = capsys.readouterr().out

    assert rc == 0
    assert not (install_env.home / ".agents").exists()
    assert "Skipped " in out
    assert str(install_env.home / ".agents" / "skills") in out


def test_install_replaces_existing_agents_directory(install_env, capsys):
    stale_dir = install_env.home / ".agents" / "skills" / "qmu"
    stale_dir.mkdir(parents=True)
    stale_file = stale_dir / "stale.md"
    stale_file.write_text("old")

    rc = cli.main(["skill", "install"])
    capsys.readouterr()

    assert rc == 0
    assert stale_dir.is_symlink()
    assert stale_dir.resolve() == (install_env.sources[0]).resolve()
    assert not stale_file.exists()


def test_install_roots_order_and_membership(install_env):
    home = install_env.home
    (home / ".codex").mkdir()
    (home / ".agents").mkdir()

    assert paths.skill_install_roots() == [
        home / ".claude" / "skills",
        home / ".codex" / "skills",
        home / ".agents" / "skills",
    ]


def test_doctor_and_installer_share_one_root_helper():
    assert meta.skill_install_roots is paths.skill_install_roots
    assert lifecycle.skill_install_roots is paths.skill_install_roots


def test_autouse_isolation_keeps_install_roots_off_the_developer_home(real_developer_home):
    """No test may write skills into the real ~/.claude, ~/.codex or ~/.agents.

    `skill install` is a MUTATING handler that the exempt-verb sweep in
    test_cli_config_errors runs for real, so every root this returns is a
    directory the suite will symlink into.
    """
    real_home = real_developer_home

    for root in paths.skill_install_roots():
        resolved = root.resolve()
        assert resolved != real_home and real_home not in resolved.parents, (
            f"install root {root} lies inside the developer's real home"
        )


def _skills_check(payload: dict) -> dict:
    return next(item for item in payload["checks"] if item["check"] == "skills")


def test_doctor_reports_ok_on_every_root_the_installer_wrote(install_env, monkeypatch, capsys):
    """Behavioral installer<->doctor agreement across MORE THAN ONE root.

    The identity guard above only proves both modules import the same helper;
    it never runs doctor's root loop with a multi-root list, which is exactly
    the OMP host this feature exists for.
    """
    (install_env.home / ".agents").mkdir()
    monkeypatch.setattr(lifecycle, "all_skill_source_dirs", lambda: list(install_env.sources))

    assert cli.main(["skill", "install"]) == 0
    capsys.readouterr()

    cli.main(["--format", "json", "doctor"])
    skills = _skills_check(json.loads(capsys.readouterr().out))
    assert skills["status"] == "ok"
    for name in install_env.names:
        for root in (".claude", ".agents"):
            assert str(install_env.home / root / "skills" / name) in skills["detail"]

    (install_env.home / ".agents" / "skills" / install_env.names[0]).unlink()
    cli.main(["--format", "json", "doctor"])
    skills = _skills_check(json.loads(capsys.readouterr().out))
    assert skills["status"] == "warn"
    assert "partial: 3 installed, 1 missing" in skills["detail"]


def _agents_home_is_a_file(home):
    (home / ".agents").write_text("not a directory")
    return home / ".agents"


def _agents_skills_is_a_file(home):
    (home / ".agents").mkdir()
    (home / ".agents" / "skills").write_text("not a directory")
    return home / ".agents" / "skills"


def _agents_skills_is_a_dangling_symlink(home):
    (home / ".agents").mkdir()
    (home / ".agents" / "skills").symlink_to(home / "gone")
    return home / ".agents" / "skills"


@pytest.mark.parametrize(
    "make_blocker",
    [_agents_home_is_a_file, _agents_skills_is_a_file, _agents_skills_is_a_dangling_symlink],
    ids=["agents-home-is-file", "agents-skills-is-file", "agents-skills-dangling-symlink"],
)
def test_unusable_agents_root_fails_operationally_without_half_installing(
    install_env, capsys, make_blocker
):
    """An unusable auto-detected root aborts before any link, as exit 1 with a remedy.

    Exit 1 (QMUError, operational) and not 4: the offending state is the
    caller's own filesystem, not a qmu-internal fault. And nothing may be
    linked into ~/.claude, or the run leaves the roots that DID work partially
    installed — which the next `qmu doctor` then reports as `partial`.
    """
    (install_env.home / ".omp" / "agent").mkdir(parents=True)
    blocker = make_blocker(install_env.home)

    rc = cli.main(["skill", "install"])
    captured = capsys.readouterr()

    assert rc == 1
    assert captured.out == ""
    assert str(blocker) in captured.err
    assert "not a directory" in captured.err
    assert "AGENTS_HOME" in captured.err
    claude_skills = install_env.home / ".claude" / "skills"
    assert not claude_skills.exists() or not list(claude_skills.iterdir())


def test_install_accepts_a_root_symlinked_to_a_real_directory(install_env, tmp_path, capsys):
    """A dotfiles layout that symlinks ~/.agents/skills elsewhere still installs."""
    real = tmp_path / "dotfiles-skills"
    real.mkdir()
    (install_env.home / ".agents").mkdir()
    (install_env.home / ".agents" / "skills").symlink_to(real)

    rc = cli.main(["skill", "install"])
    capsys.readouterr()

    assert rc == 0
    for name, src in zip(install_env.names, install_env.sources):
        assert (real / name).is_symlink()
        assert (real / name).resolve() == src.resolve()


def test_reinstall_reports_current_and_writes_nothing(install_env, capsys):
    """A re-run must say so, and must not rewrite links that are already right.

    Before this, every (skill, root) pair printed "Skill installed" whether it
    had just been created, had been left alone, or had been silently repointed
    from another checkout — so a re-run was indistinguishable from a first
    install and the one outcome worth seeing was invisible.
    """
    (install_env.home / ".agents").mkdir()
    assert cli.main(["skill", "install"]) == 0
    first = capsys.readouterr().out
    links = [
        install_env.home / root / "skills" / name
        for root in (".claude", ".agents")
        for name in install_env.names
    ]
    before = {p: p.lstat().st_mtime_ns for p in links}

    assert cli.main(["skill", "install"]) == 0
    second = capsys.readouterr().out

    assert "4 installed" in first
    assert "All 4 links in 2 roots already current — nothing to do." in second
    assert "installed" not in second
    # Untouched, not removed-and-recreated: a live agent session reads through
    # these links, and churning them on a no-op re-run is what made the stale
    # -target case impossible to spot.
    assert {p: p.lstat().st_mtime_ns for p in links} == before


def test_reinstall_from_another_checkout_reports_the_target_it_replaced(
    install_env, tmp_path, capsys
):
    """The stale-checkout case: relinked, naming the tree it pointed at."""
    stale_src = tmp_path / "stale-checkout" / "skills" / install_env.names[0]
    stale_src.mkdir(parents=True)
    (stale_src / "SKILL.md").write_text("# stale\n")
    dst = install_env.home / ".claude" / "skills" / install_env.names[0]
    dst.parent.mkdir(parents=True)
    dst.symlink_to(stale_src)

    assert cli.main(["skill", "install"]) == 0
    out = capsys.readouterr().out

    assert f"relinked  {dst} -> {install_env.sources[0]}  (was {stale_src})" in out
    assert "1 relinked" in out
    assert dst.resolve() == install_env.sources[0].resolve()


@pytest.mark.parametrize("shape", ["dir", "file"])
def test_install_replaces_real_content_and_says_so(install_env, capsys, shape):
    """A real dir or file at the destination is replaced, visibly.

    The `file` case also pins an error-class bug: a plain file reached
    shutil.rmtree() and raised NotADirectoryError into cli's catch-all as exit
    4, the code reserved for infra faults.
    """
    dst = install_env.home / ".claude" / "skills" / install_env.names[0]
    dst.parent.mkdir(parents=True)
    if shape == "dir":
        dst.mkdir()
        (dst / "stale.md").write_text("stale\n")
    else:
        dst.write_text("not a skill\n")

    assert cli.main(["skill", "install"]) == 0
    out = capsys.readouterr().out

    assert f"replaced  {dst} -> {install_env.sources[0]}  (removed what was there)" in out
    assert "1 replaced" in out
    assert dst.is_symlink() and dst.resolve() == install_env.sources[0].resolve()


def test_install_json_envelope_carries_every_link_and_the_tally(install_env, capsys):
    """`--format json` was accepted and silently ignored: the handler printed
    plain text on every path, so an agent asking for JSON got rc 0 and
    unparseable stdout."""
    (install_env.home / ".agents").mkdir()
    assert cli.main(["--format", "json", "skill", "install"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["ok"] is True
    assert payload["counts"] == {
        "installed": 4, "relinked": 0, "replaced": 0, "current": 0,
    }
    assert len(payload["links"]) == sum(payload["counts"].values())
    assert {link["status"] for link in payload["links"]} == {"installed"}
    assert payload["roots"] == [
        str(install_env.home / ".claude" / "skills"),
        str(install_env.home / ".agents" / "skills"),
    ]

    assert cli.main(["--format", "json", "skill", "install"]) == 0
    again = json.loads(capsys.readouterr().out)
    assert again["counts"]["current"] == 4
    assert all(link["previous_target"] is None for link in again["links"])


def _seed_mixed_state(install_env, tmp_path):
    """One link in each of the four states, across two roots.

    .claude/qmu            -> stale checkout   (relinked)
    .claude/qmu-linux-kbuild  real directory   (replaced)
    .agents/qmu            -> this checkout    (current)
    .agents/qmu-linux-kbuild  absent           (installed)
    """
    stale_src = tmp_path / "stale-checkout" / "skills" / install_env.names[0]
    stale_src.mkdir(parents=True, exist_ok=True)
    claude = install_env.home / ".claude" / "skills"
    agents = install_env.home / ".agents" / "skills"
    for root in (claude, agents):
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
    (claude / install_env.names[0]).symlink_to(stale_src)
    (claude / install_env.names[1]).mkdir()
    (agents / install_env.names[0]).symlink_to(install_env.sources[0])
    return stale_src, claude, agents


def test_text_and_json_agree_on_a_mixed_run(install_env, tmp_path, capsys):
    """Same seeded state, both renderers: every status the text lists is the
    status JSON carries, `previous_target` is set exactly on the relinked
    link, and the text tally equals JSON `counts`."""
    stale_src, claude, agents = _seed_mixed_state(install_env, tmp_path)
    assert cli.main(["skill", "install"]) == 0
    text = capsys.readouterr().out

    _seed_mixed_state(install_env, tmp_path)
    assert cli.main(["--format", "json", "skill", "install"]) == 0
    payload = json.loads(capsys.readouterr().out)

    expected = {
        str(claude / install_env.names[0]): ("relinked", str(stale_src)),
        str(claude / install_env.names[1]): ("replaced", None),
        str(agents / install_env.names[0]): ("current", None),
        str(agents / install_env.names[1]): ("installed", None),
    }
    assert {
        link["path"]: (link["status"], link["previous_target"])
        for link in payload["links"]
    } == expected
    assert payload["counts"] == {
        "installed": 1, "relinked": 1, "replaced": 1, "current": 1,
    }

    lines = text.splitlines()
    assert (
        f"relinked  {claude / install_env.names[0]} -> {install_env.sources[0]}"
        f"  (was {stale_src})"
    ) in lines
    assert (
        f"replaced  {claude / install_env.names[1]} -> {install_env.sources[1]}"
        "  (removed what was there)"
    ) in lines
    assert f"installed {agents / install_env.names[1]} -> {install_env.sources[1]}" in lines
    # current is tallied, never listed
    assert not any(line.startswith("current") for line in lines)
    assert "4 links in 2 roots: 1 installed, 1 relinked, 1 replaced, 1 current." in lines
    for path in expected:
        assert Path(path).is_symlink()
        assert Path(path).resolve() in {s.resolve() for s in install_env.sources}, path
