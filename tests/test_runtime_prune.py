from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

import qmu.runtime as runtime
from qmu.output import write_output_result
from qmu.paths import runtime_root, spill_root, ssh_control_dir
from qmu.runtime import (
    RuntimeArtifact,
    RuntimePruneResult,
    mark_spill_artifact,
    probe_unix_socket,
    prune_runtime_artifacts,
    spill_marker_path,
)


@pytest.fixture(autouse=True)
def short_isolated_runtime(tmp_path, monkeypatch):
    """Keep real AF_UNIX paths short and isolate every runtime artifact."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("QMU_TEMP_DIR", "runtime")


def _marked_spill(name: str, *, created_at: float) -> Path:
    artifact = spill_root() / name
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("owned spill")
    mark_spill_artifact(artifact, created_at=created_at)
    return artifact


def _stale_control(name: str, *, mtime: float) -> Path:
    path = ssh_control_dir() / name
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        control.bind(str(path))
    finally:
        control.close()
    os.utime(path, (mtime, mtime))
    return path


def _artifact_pairs(items) -> list[tuple[str, Path]]:
    return [(item.kind, item.path) for item in items]


def test_prune_runtime_removes_marked_spill_at_age_boundary():
    artifact = _marked_spill("old.txt", created_at=900.0)
    marker = spill_marker_path(artifact)

    result = prune_runtime_artifacts(older_than_seconds=100.0, now=1000.0)

    assert result.removed == (
        RuntimeArtifact(
            kind="spill",
            path=artifact,
            created_at=900.0,
            marker_path=marker,
        ),
    )
    assert not artifact.exists()
    assert not marker.exists()


def test_prune_runtime_keeps_younger_marked_spill_even_with_old_marker_mtime():
    artifact = _marked_spill("young.txt", created_at=900.1)
    marker = spill_marker_path(artifact)
    os.utime(marker, (1.0, 1.0))

    result = prune_runtime_artifacts(older_than_seconds=100.0, now=1000.0)

    assert result == RuntimePruneResult((), (), ())
    assert artifact.read_text() == "owned spill"
    assert marker.exists()


def test_prune_runtime_does_not_remove_explicit_output():
    explicit = spill_root() / "manual.json"
    write_output_result(
        {"value": "x" * 100}, fmt="json", out_path=explicit, stem="manual"
    )
    os.utime(explicit, (1.0, 1.0))

    result = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert result.removed == ()
    assert explicit.exists()
    assert not spill_marker_path(explicit).exists()


def test_prune_runtime_leaves_unmarked_spill_lookalike_untouched():
    lookalike = spill_root() / "20260709" / "exec-old.txt"
    lookalike.parent.mkdir()
    lookalike.write_text("user-owned")
    os.utime(lookalike, (1.0, 1.0))

    prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert lookalike.read_text() == "user-owned"


def test_prune_runtime_skips_malformed_marker():
    artifact = spill_root() / "bad.txt"
    artifact.write_text("preserve me")
    marker = spill_marker_path(artifact)
    marker.write_bytes(b'{"schema":')

    result = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert result.removed == ()
    assert artifact.read_text() == "preserve me"
    assert marker.read_bytes() == b'{"schema":'


def test_prune_runtime_preserves_empty_basename_marker_without_aborting():
    marker = spill_root() / ".qmu-owned.json"
    marker_payload = {
        "schema": 1,
        "kind": "spill",
        "artifact": "",
        "created_at": 1.0,
        "st_dev": 0,
        "st_ino": 0,
        "st_size": 0,
        "st_mtime_ns": 0,
    }
    marker_bytes = json.dumps(marker_payload, sort_keys=True).encode()
    marker.write_bytes(marker_bytes)
    valid_artifact = _marked_spill("valid.txt", created_at=1.0)

    result = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert _artifact_pairs(result.removed) == [("spill", valid_artifact)]
    assert marker.read_bytes() == marker_bytes


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        pytest.param("schema", 2, id="wrong-schema"),
        pytest.param("kind", "user-output", id="wrong-kind"),
        pytest.param("artifact", "../escape", id="traversal-artifact"),
    ],
)
def test_prune_runtime_skips_semantically_invalid_marker(field, invalid_value):
    artifact = _marked_spill("invalid.txt", created_at=1.0)
    marker = spill_marker_path(artifact)
    payload = json.loads(marker.read_text())
    payload[field] = invalid_value
    marker_bytes = json.dumps(payload, sort_keys=True).encode()
    marker.write_bytes(marker_bytes)

    result = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert result.removed == ()
    assert artifact.read_text() == "owned spill"
    assert marker.read_bytes() == marker_bytes


def test_prune_runtime_does_not_follow_artifact_or_marker_symlink(tmp_path):
    symlinked_artifact = _marked_spill("artifact-link.txt", created_at=1.0)
    artifact_marker = spill_marker_path(symlinked_artifact)
    symlinked_artifact.unlink()
    user_artifact = tmp_path / "user-artifact"
    user_artifact.write_text("outside artifact")
    symlinked_artifact.symlink_to(user_artifact.resolve())

    marker_artifact = _marked_spill("marker-link.txt", created_at=1.0)
    symlinked_marker = spill_marker_path(marker_artifact)
    symlinked_marker.unlink()
    user_marker = tmp_path / "user-marker"
    user_marker.write_text("outside marker")
    symlinked_marker.symlink_to(user_marker.resolve())

    result = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert result.removed == ()
    assert symlinked_artifact.is_symlink()
    assert artifact_marker.exists()
    assert user_artifact.read_text() == "outside artifact"
    assert marker_artifact.read_text() == "owned spill"
    assert symlinked_marker.is_symlink()
    assert user_marker.read_text() == "outside marker"


@pytest.mark.parametrize("replacement", ["modify", "replace"])
def test_prune_runtime_preserves_modified_or_replaced_spill(replacement):
    artifact = _marked_spill("replaced.txt", created_at=1.0)
    marker = spill_marker_path(artifact)
    replacement_text = f"user {replacement} with different size"
    if replacement == "replace":
        artifact.unlink()
    artifact.write_text(replacement_text)

    result = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert result.removed == ()
    assert artifact.read_text() == replacement_text
    assert marker.exists()


def test_prune_runtime_preserves_spill_replaced_after_identity_check(monkeypatch):
    artifact = _marked_spill("raced.txt", created_at=1.0)
    marker = spill_marker_path(artifact)
    replacement = b"user replacement during prune"
    real_lstat = Path.lstat
    artifact_lstats = 0

    def replace_after_identity_check(path):
        nonlocal artifact_lstats
        observed = real_lstat(path)
        if path == artifact:
            artifact_lstats += 1
            if artifact_lstats == 1:
                artifact.unlink()
                artifact.write_bytes(replacement)
        return observed

    monkeypatch.setattr(Path, "lstat", replace_after_identity_check)
    result = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert result.removed == ()
    assert artifact.read_bytes() == replacement
    assert marker.exists()


def test_prune_runtime_removes_orphaned_valid_marker_when_target_is_already_gone():
    artifact = _marked_spill("gone.txt", created_at=1.0)
    marker = spill_marker_path(artifact)
    artifact.unlink()

    result = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert _artifact_pairs(result.removed) == [("spill", artifact)]
    assert not marker.exists()


def test_probe_unix_socket_reports_live_for_listening_socket():
    path = ssh_control_dir() / "cm-live-probe"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen()
        assert probe_unix_socket(path, timeout=0.1) == "live"


def test_probe_unix_socket_reports_stale_for_refused_socket():
    path = _stale_control("cm-stale-probe", mtime=1.0)
    assert probe_unix_socket(path, timeout=0.1) == "stale"


def test_probe_unix_socket_reports_gone_for_missing_path():
    assert probe_unix_socket(ssh_control_dir() / "cm-gone", timeout=0.1) == "gone"


def test_probe_unix_socket_reports_indeterminate_for_non_socket():
    path = ssh_control_dir() / "cm-regular-probe"
    path.write_text("not a socket")
    assert probe_unix_socket(path, timeout=0.1) == "indeterminate"


@pytest.mark.parametrize(
    "connect_error",
    [
        pytest.param(TimeoutError("timed out"), id="timeout"),
        pytest.param(PermissionError("denied"), id="permission"),
    ],
)
def test_probe_unix_socket_maps_uncertain_connect_errors_to_indeterminate(
    connect_error, monkeypatch
):
    path = _stale_control("cm-uncertain-probe", mtime=1.0)

    class UncertainSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            self.close()

        def settimeout(self, _timeout):
            pass

        def connect(self, _path):
            raise connect_error

        def close(self):
            pass

    monkeypatch.setattr(runtime.socket, "socket", lambda *_args: UncertainSocket())

    assert probe_unix_socket(path, timeout=0.1) == "indeterminate"


def test_prune_runtime_live_control_socket_is_always_skipped_even_when_old():
    path = ssh_control_dir() / "cm-live"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen()
        os.utime(path, (1.0, 1.0))

        result = prune_runtime_artifacts(older_than_seconds=100.0, now=1000.0)

        assert _artifact_pairs(result.skipped_live) == [("ssh-control", path)]
        assert result.removed == ()
        assert path.exists()


def test_prune_runtime_removes_stale_control_socket_when_old():
    path = _stale_control("cm-stale", mtime=900.0)

    result = prune_runtime_artifacts(older_than_seconds=100.0, now=1000.0)

    assert _artifact_pairs(result.removed) == [("ssh-control", path)]
    assert not path.exists()


def test_prune_runtime_preserves_same_socket_that_becomes_live_between_probes(
    monkeypatch,
):
    path = ssh_control_dir() / "cm-becomes-live"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
        os.utime(path, (1.0, 1.0))
        initial_stat = path.lstat()
        real_probe = runtime.probe_unix_socket
        transitioned = False

        def become_live_after_refusal(candidate):
            nonlocal transitioned
            state = real_probe(candidate, timeout=0.1)
            if not transitioned:
                assert state == "stale"
                listener.listen()
                transitioned = True
            return state

        monkeypatch.setattr(runtime, "probe_unix_socket", become_live_after_refusal)
        result = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)
        current_stat = path.lstat()

        assert _artifact_pairs(result.skipped_live) == [("ssh-control", path)]
        assert result.removed == ()
        assert (
            current_stat.st_dev,
            current_stat.st_ino,
            current_stat.st_mode,
        ) == (
            initial_stat.st_dev,
            initial_stat.st_ino,
            initial_stat.st_mode,
        )
    finally:
        listener.close()


def test_prune_runtime_keeps_stale_control_socket_when_young():
    path = _stale_control("cm-young", mtime=900.1)

    result = prune_runtime_artifacts(older_than_seconds=100.0, now=1000.0)

    assert result.removed == ()
    assert path.exists()


def test_prune_runtime_skips_regular_cm_prefixed_file():
    path = ssh_control_dir() / "cm-user-file"
    path.write_text("user-owned")
    os.utime(path, (1.0, 1.0))

    result = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert result.removed == ()
    assert path.read_text() == "user-owned"


def test_prune_runtime_skips_non_cm_and_nested_sockets():
    direct = _stale_control("not-qmu.sock", mtime=1.0)
    nested_dir = ssh_control_dir() / "nested"
    nested_dir.mkdir()
    nested = nested_dir / "cm-nested"
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        control.bind(str(nested))
    finally:
        control.close()
    os.utime(nested, (1.0, 1.0))

    prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert direct.exists()
    assert nested.exists()


def test_prune_runtime_skips_indeterminate_control_probe(monkeypatch):
    path = _stale_control("cm-uncertain", mtime=1.0)
    monkeypatch.setattr(runtime, "probe_unix_socket", lambda _path: "indeterminate")

    result = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert _artifact_pairs(result.skipped_indeterminate) == [("ssh-control", path)]
    assert path.exists()


def test_prune_runtime_treats_gone_control_after_probe_as_benign(monkeypatch):
    path = _stale_control("cm-gone-race", mtime=1.0)

    def remove_during_probe(candidate):
        candidate.unlink()
        return "gone"

    monkeypatch.setattr(runtime, "probe_unix_socket", remove_during_probe)
    result = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert result == RuntimePruneResult((), (), ())
    assert not path.exists()


def test_prune_runtime_preserves_control_replaced_after_stale_probe(monkeypatch):
    path = _stale_control("cm-raced", mtime=1.0)
    replacement = b"user replacement"

    def replace_during_probe(candidate):
        candidate.unlink()
        candidate.write_bytes(replacement)
        return "stale"

    monkeypatch.setattr(runtime, "probe_unix_socket", replace_during_probe)
    result = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert result.removed == ()
    assert _artifact_pairs(result.skipped_indeterminate) == [("ssh-control", path)]
    assert path.read_bytes() == replacement


def test_prune_runtime_does_not_touch_sibling_qmu_names(tmp_path):
    siblings = [
        tmp_path / "qmu-linux-owned",
        tmp_path / "qmu-passt.sock",
        tmp_path / "qmu-random",
    ]
    for sentinel in siblings:
        sentinel.write_text(sentinel.name)
    unrelated = runtime_root() / "unrelated"
    unrelated.parent.mkdir(parents=True, exist_ok=True)
    unrelated.write_text("inside explicit root")

    prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert [sentinel.read_text() for sentinel in siblings] == [
        "qmu-linux-owned",
        "qmu-passt.sock",
        "qmu-random",
    ]
    assert unrelated.read_text() == "inside explicit root"


def test_prune_runtime_removes_only_empty_owned_date_directories():
    root = spill_root()
    old = _marked_spill("20260701/old.txt", created_at=1.0)
    removed_parent = old.parent
    nonempty_parent = spill_root() / "20260702"
    nonempty_parent.mkdir()
    sentinel = nonempty_parent / "manual.txt"
    sentinel.write_text("preserve")
    unrelated_empty = spill_root() / "20260703"
    unrelated_empty.mkdir()

    prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert not removed_parent.exists()
    assert sentinel.read_text() == "preserve"
    assert unrelated_empty.is_dir()
    assert root.is_dir()


@pytest.mark.parametrize(
    "directory_name",
    [
        pytest.param("\u0662\u0660\u0662\u0666\u0660\u0667\u0660\u0661", id="unicode-digits"),
        pytest.param("20260230", id="impossible-date"),
    ],
)
def test_prune_runtime_preserves_nonproducer_date_directory(directory_name):
    artifact = _marked_spill(f"{directory_name}/old.txt", created_at=1.0)
    parent = artifact.parent

    result = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert _artifact_pairs(result.removed) == [("spill", artifact)]
    assert parent.is_dir()
    assert list(parent.iterdir()) == []


def test_prune_runtime_is_idempotent():
    spill = _marked_spill("old.txt", created_at=1.0)
    control = _stale_control("cm-old", mtime=1.0)

    first = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)
    second = prune_runtime_artifacts(older_than_seconds=0.0, now=1000.0)

    assert set(_artifact_pairs(first.removed)) == {
        ("spill", spill),
        ("ssh-control", control),
    }
    assert second == RuntimePruneResult((), (), ())


@pytest.mark.parametrize(
    "invalid_age",
    [
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="positive-infinity"),
        pytest.param(float("-inf"), id="negative-infinity"),
    ],
)
def test_prune_runtime_rejects_nonfinite_age_without_removing_artifacts(invalid_age):
    artifact = _marked_spill("preserved.txt", created_at=1.0)
    marker = spill_marker_path(artifact)
    control = _stale_control("cm-preserved", mtime=1.0)

    with pytest.raises(ValueError):
        prune_runtime_artifacts(older_than_seconds=invalid_age, now=1000.0)

    assert artifact.read_text() == "owned spill"
    assert marker.exists()
    assert control.exists()


@pytest.mark.parametrize(
    "invalid_now",
    [
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="positive-infinity"),
        pytest.param(float("-inf"), id="negative-infinity"),
    ],
)
def test_prune_runtime_rejects_nonfinite_now_without_removing_artifacts(invalid_now):
    artifact = _marked_spill("preserved.txt", created_at=1.0)
    marker = spill_marker_path(artifact)
    control = _stale_control("cm-preserved", mtime=1.0)

    with pytest.raises(ValueError):
        prune_runtime_artifacts(older_than_seconds=0.0, now=invalid_now)

    assert artifact.read_text() == "owned spill"
    assert marker.exists()
    assert control.exists()


def test_prune_runtime_rejects_negative_age():
    with pytest.raises(ValueError):
        prune_runtime_artifacts(older_than_seconds=-0.1, now=1000.0)
