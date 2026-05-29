"""ERG-7: `qmu config init` is idempotent.

Re-running `qmu config init` when a qmu.toml already exists is a BENIGN no-op,
not an error. The agreed contract:

  * first run  -> creates ./qmu.toml, exit 0
  * second run -> file already exists, exit 0 (idempotent success) with a clear
    message; the existing file is NOT overwritten.

The old code reused exit 1 ("operation failed") for this benign case, which made
an agent treat a perfectly fine pre-existing config as a failure.

config init writes to Path.cwd()/qmu.toml, so each test chdir's into a fresh
empty temp dir (the autouse isolate_qmu_env fixture isolates cache/config dirs
but does not change CWD).

Findings exercised: ERG-7 / config-init-exit-code.
"""

from __future__ import annotations

import pytest

from qmu import cli


@pytest.fixture
def in_empty_dir(tmp_path, monkeypatch):
    """chdir into a fresh empty dir so config init's CWD target is pristine."""
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    return work


def test_config_init_creates_file_exit_0(in_empty_dir, capsys):
    rc = cli.main(["config", "init"])
    assert rc == 0
    target = in_empty_dir / "qmu.toml"
    assert target.exists()
    assert target.read_text().strip() != ""


def test_config_init_already_exists_is_exit_0(in_empty_dir, capsys):
    """Second run is idempotent success (exit 0), not exit 1."""
    assert cli.main(["config", "init"]) == 0
    capsys.readouterr()  # drop first-run output

    rc = cli.main(["config", "init"])
    assert rc == 0  # idempotent — NOT a failure

    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "already exists" in combined


def test_config_init_does_not_overwrite_existing(in_empty_dir, capsys):
    """The pre-existing file's contents are preserved across a re-run."""
    target = in_empty_dir / "qmu.toml"
    target.write_text("# user-customized config\n[machine]\nmemory = \"99G\"\n")
    before = target.read_text()

    rc = cli.main(["config", "init"])

    assert rc == 0
    assert target.read_text() == before  # untouched
