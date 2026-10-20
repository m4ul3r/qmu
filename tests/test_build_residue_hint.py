"""The --build-residue held-back advice must name a recovery that can work.

Residue is eligible when it is OLDER than the --older-than threshold, so the
recovery for "held back by the cutoff" is a SMALLER threshold (down to the
600s floor), never a larger one (#164). These tests pin the wording and the
floor error's `hint`, so neither can regress to a guaranteed no-op again.
"""
import argparse
from types import SimpleNamespace

import pytest

from qmu.commands.lifecycle import (
    MIN_BUILD_RESIDUE_AGE,
    _handle_prune_build_residue,
    _residue_lines,
)
from qmu.instance import QMUError


def _fake_report(held_groups=("linux-6.1.75", "linux-6.1.76")):
    return SimpleNamespace(
        eligible=SimpleNamespace(files=0, bytes=0, groups=[]),
        held_back=SimpleNamespace(
            files=14092, bytes=2050723840, groups=list(held_groups), reasons=["modified within 86400s"]
        ),
        refused=SimpleNamespace(files=0, bytes=0, groups=[], reasons=[]),
    )


def test_held_back_advice_names_a_smaller_older_than():
    text = _residue_lines(_fake_report(), dry_run=True, older_than=86400)

    held_line = next(line for line in text if line.startswith("Held back by the --older-than"))
    # A larger threshold can only hold back more; the recovery is the smaller one.
    assert "with a smaller --older-than" in held_line
    assert "larger" not in held_line


def test_held_back_advice_names_the_floor_and_a_copyable_command():
    text = _residue_lines(_fake_report(), dry_run=True, older_than=86400)

    held_line = next(line for line in text if line.startswith("Held back by the --older-than"))
    assert f"{MIN_BUILD_RESIDUE_AGE:g}s floor" in held_line
    assert f"qmu prune --build-residue --older-than {MIN_BUILD_RESIDUE_AGE:g}" in held_line


def test_no_held_back_line_without_held_back_residue():
    report = _fake_report(held_groups=())
    report.held_back.files = 0
    text = _residue_lines(report, dry_run=True, older_than=86400)

    assert not any(line.startswith("Held back by the --older-than") for line in text)


def test_floor_error_carries_the_real_recovery_as_hint():
    args = argparse.Namespace(keep_logs=False, older_than=0)

    with pytest.raises(QMUError) as excinfo:
        _handle_prune_build_residue(args)

    hint = excinfo.value.hint
    # Not the generic default hint: the recovery is the floor itself.
    assert "qmu status --vm" not in hint
    assert f"--older-than {MIN_BUILD_RESIDUE_AGE:g}" in hint
    assert "qmu cache du --older-than 0" in hint
