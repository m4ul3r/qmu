"""A launched process is not a successful requested SSH readiness check."""

from __future__ import annotations

import json

import pytest

from qmu import cli
from qmu.commands import lifecycle
from qmu.instance import VMInstance, load_instance, save_instance


@pytest.fixture
def launch_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "qmu.toml").write_text('[boot]\nkernel = "Image"\n')
    serial = tmp_path / "readiness.serial.log"
    serial.write_text("boot observation retained\n")
    inst = VMInstance(
        vm_id="readiness", pid=0, qmp_socket=str(tmp_path / "unused.qmp"),
        ssh_port=10021, ssh_key=str(tmp_path / "unused-key"), gdb_port=None,
        serial_log=str(serial), kernel="Image", rootfs=None, memory="128M",
        cpus=1, cmdline="console=ttyS0", profile="exploit-dev",
        started_at="2026-09-14T00:00:00Z",
    )
    state = {"ready": False, "forbid_probe": False}

    def launch(**kwargs):
        inst.harness = kwargs["harness"]
        if inst.harness:
            inst.ssh_port = None
        save_instance(inst)
        return inst

    class SSH:
        def is_ready(self, timeout=2):
            assert not state["forbid_probe"], "an opted-out readiness probe ran"
            return state["ready"]

    monkeypatch.setattr(lifecycle, "launch_vm", launch)
    monkeypatch.setattr(lifecycle, "_make_ssh", lambda inst: SSH())
    monkeypatch.setattr(lifecycle.time, "sleep", lambda _: None)
    return inst, serial, state


@pytest.mark.parametrize("output_format", ["json", "ndjson", "text"])
def test_requested_ssh_timeout_fails_and_retains_vm(launch_env, capsys, output_format):
    """#72: an expired --ssh-timeout is the timeout class (124), the same code
    `run` exits for the same condition — not the SSH-transport class (4). The
    VM, its metadata and serial log are retained; the envelope says
    `timed_out: true` and names the follow-up commands."""
    inst, serial, _ = launch_env

    rc = cli.main(["launch", "--ssh-timeout", "0", "--format", output_format])
    output = capsys.readouterr()

    assert rc == 124
    if output_format == "text":
        assert "SSH" in output.out
        assert "timeout" in output.out
        assert "[qmu] Error: SSH did not become ready" in output.err
        assert f"qmu log --vm {inst.vm_id} --tail 50" in output.err
    else:
        payload = json.loads(output.out)
        assert payload["ok"] is False
        assert payload["timed_out"] is True
        assert payload["ssh_error"] is True
        assert payload["error_type"] == "TimeoutError"
        assert "SSH" in payload["error"]
        assert payload["ssh_status"] == "timeout"
        assert f"qmu log --vm {inst.vm_id} --tail 50" in payload["hint"]
        assert f"qmu status --vm {inst.vm_id}" in payload["hint"]
        assert "--ssh-timeout" in payload["hint"]
        assert payload["vm_id"] == inst.vm_id
        assert payload["serial_log"] == str(serial)
    assert load_instance(inst.vm_id) is not None
    assert serial.read_text() == "boot observation retained\n"


def test_successful_ssh_readiness_remains_success(launch_env, capsys):
    _, _, state = launch_env
    state["ready"] = True

    rc = cli.main(["launch", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["ok"] is True
    assert payload["ssh_status"] == "ready"
    assert "error" not in payload


@pytest.mark.parametrize("mode", ["--no-wait-ssh", "--harness"])
def test_opted_out_readiness_is_not_a_launch_failure(launch_env, capsys, mode):
    _, _, state = launch_env
    state["forbid_probe"] = True

    rc = cli.main(["launch", mode, "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["ok"] is True
    assert payload["ssh_status"] != "ready"
    assert "error" not in payload


# ---------------------------------------------------------------------------
# `unknown_kernel_params: []` after an opted-out readiness wait read exactly
# like "checked and clean". The check needs a booted guest; when it did not
# run, the JSON must say so rather than report an empty finding.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["--no-wait-ssh", "--harness"])
def test_unchecked_kernel_params_are_null_not_empty(launch_env, capsys, mode):
    _, _, state = launch_env
    state["forbid_probe"] = True

    cli.main(["launch", mode, "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["unknown_kernel_params"] is None
    assert payload["unknown_kernel_params_by_source"] is None


def test_checked_kernel_params_stay_a_list(launch_env, capsys, monkeypatch):
    _, _, state = launch_env
    state["ready"] = True
    monkeypatch.setattr(
        lifecycle, "_warn_unknown_kernel_params",
        lambda inst: {"all": [], "operator": [], "profile": []},
    )

    cli.main(["launch", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["unknown_kernel_params"] == []
    assert payload["unknown_kernel_params_by_source"] == {
        "operator": [], "profile": [],
    }


def test_launch_json_carries_the_instance_record(launch_env, capsys):
    """An agent should never need to cat the instance file after launch."""
    inst, _, state = launch_env
    state["ready"] = True
    inst.kvm = True
    inst.cmdline_override = True

    cli.main(["launch", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["kvm"] is True
    assert payload["cmdline"] == inst.cmdline
    assert payload["rootfs"] == inst.rootfs
    assert payload["qmp_socket"] == inst.qmp_socket
    assert payload["qemu_log"].endswith("readiness.qemu.log")
    assert payload["profile_applied"] is False
    assert payload["arch"]



# ---------------------------------------------------------------------------
# A serial log still empty after NO_CONSOLE_OUTPUT_SECONDS of SSH waiting is
# not a slow boot: the kernel is writing to a console device this machine
# does not have (the x86 `console=ttyS0` profile on an ARM virt guest), and
# sitting out the whole --ssh-timeout only delays the same answer.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("output_format", ["json", "text"])
def test_empty_serial_log_fails_fast_as_no_console_output(
    launch_env, capsys, monkeypatch, output_format
):
    inst, serial, _ = launch_env
    serial.write_text("")
    monkeypatch.setattr(lifecycle, "NO_CONSOLE_OUTPUT_SECONDS", 0.0)

    rc = cli.main([
        "launch", "--arch", "aarch64", "--ssh-timeout", "600",
        "--format", output_format,
    ])
    output = capsys.readouterr()

    assert rc == 4
    if output_format == "text":
        assert "no-console-output" in output.out
        assert "console=" in output.err and "ttyAMA0" in output.err
        assert "-M/-cpu" in output.err
    else:
        payload = json.loads(output.out)
        assert payload["ok"] is False
        assert payload["ssh_status"] == "no-console-output"
        assert payload["error_type"] == "SSHError"
        assert "console=" in payload["error"] and "ttyAMA0" in payload["error"]
        assert "-M/-cpu" in payload["error"]
        assert "No console output" in payload["error"]
    # Retained for inspection, exactly like the SSH-timeout path.
    assert load_instance(inst.vm_id) is not None


def test_serial_output_keeps_the_ordinary_timeout_path(launch_env, capsys, monkeypatch):
    """Console output means the guest is booting; an SSH miss is a timeout."""
    _, serial, _ = launch_env
    assert serial.stat().st_size > 0
    monkeypatch.setattr(lifecycle, "NO_CONSOLE_OUTPUT_SECONDS", 0.0)

    rc = cli.main(["launch", "--ssh-timeout", "0", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 124
    assert payload["ssh_status"] == "timeout"


def test_console_silence_is_not_checked_before_the_grace_period(
    launch_env, capsys, monkeypatch
):
    _, serial, _ = launch_env
    serial.write_text("")
    monkeypatch.setattr(lifecycle, "NO_CONSOLE_OUTPUT_SECONDS", 3600.0)

    rc = cli.main(["launch", "--ssh-timeout", "0", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 124
    assert payload["ssh_status"] == "timeout"


# ---------------------------------------------------------------------------
# Every launch-time warning has a JSON mirror; stderr keeps the text.
# ---------------------------------------------------------------------------


def test_launch_json_carries_warnings_config_sources_and_replaced(
    launch_env, capsys, tmp_path
):
    inst, _, state = launch_env
    state["ready"] = True
    (tmp_path / "qmu.toml").write_text(
        '[boot]\nkernel = "Image"\ncmdline = "console=ttyS0 root=/dev/sda nokaslr"\n'
    )

    rc = cli.main([
        "launch", "--profile", "exploit-test", "--append", "kasan.faul=panic",
        "--format", "json",
    ])
    output = capsys.readouterr()
    payload = json.loads(output.out)

    assert rc == 0
    assert payload["config_sources"] == [str(tmp_path.resolve() / "qmu.toml")]
    assert f"[qmu] config: {tmp_path.resolve() / 'qmu.toml'}" in output.err
    assert payload["replaced"] is None
    warnings = payload["warnings"]
    assert any("--profile exploit-test overrides" in w and "nokaslr" in w for w in warnings)
    assert any("kasan.faul" in w and "kasan.fault" in w for w in warnings)
    # stderr still carries the text form of each
    assert "dropped: nokaslr" in output.err
    assert "kasan.faul" in output.err


def test_launch_json_warnings_empty_and_no_config_when_nothing_applies(
    launch_env, capsys, tmp_path, monkeypatch
):
    inst, _, state = launch_env
    state["ready"] = True
    (tmp_path / "qmu.toml").unlink()

    rc = cli.main(["launch", "--kernel", "Image", "--format", "json"])
    output = capsys.readouterr()
    payload = json.loads(output.out)

    assert rc == 0
    assert payload["warnings"] == []
    assert payload["config_sources"] == []
    assert "[qmu] config:" not in output.err


def test_launch_json_reports_the_replaced_vm(launch_env, capsys, monkeypatch):
    inst, _, state = launch_env
    state["ready"] = True
    old = VMInstance(
        vm_id="readiness", pid=777, qmp_socket="/tmp/old.qmp", ssh_port=1,
        ssh_key=None, gdb_port=None, serial_log="/tmp/old.serial.log",
        kernel="Image", rootfs=None, memory="1G", cpus=1, cmdline="x",
        profile="exploit-dev", started_at="2026-01-01T00:00:00Z",
    )
    monkeypatch.setattr(lifecycle, "load_instance", lambda name: old)
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: True)
    monkeypatch.setattr(lifecycle, "_kill_vm", lambda i, **kw: None)

    rc = cli.main(["launch", "--name", "readiness", "--format", "json"])
    output = capsys.readouterr()
    payload = json.loads(output.out)

    assert rc == 0
    assert payload["replaced"] == {"vm_id": "readiness", "pid": 777}
    assert any("replaced existing VM 'readiness' (pid=777)" in w for w in payload["warnings"])
    assert "Replacing existing VM 'readiness' (pid=777)" in output.err


def test_harness_attached_rootfs_note_is_mirrored_in_json(launch_env, capsys, tmp_path):
    inst, _, _ = launch_env
    inst.rootfs = "/var/rootfs.img"
    (tmp_path / "qmu.toml").write_text(
        '[boot]\nkernel = "Image"\n[drive]\nrootfs = "/var/rootfs.img"\n'
    )

    rc = cli.main(["launch", "--harness", "--format", "json"])
    output = capsys.readouterr()
    payload = json.loads(output.out)

    assert rc == 0
    expected = (
        "attached rootfs /var/rootfs.img (from [drive] rootfs in project "
        f"{(tmp_path / 'qmu.toml').resolve()};"
    )
    assert any(expected in w for w in payload["warnings"])
    assert expected in output.err


def test_harness_attached_rootfs_note_names_the_flag(launch_env, capsys):
    """`--rootfs` on the command line is not "from config"."""
    inst, _, _ = launch_env
    inst.rootfs = "/var/flag.img"

    rc = cli.main(["launch", "--harness", "--rootfs", "/var/flag.img", "--format", "json"])
    output = capsys.readouterr()
    payload = json.loads(output.out)

    assert rc == 0
    assert any("attached rootfs /var/flag.img (from --rootfs;" in w for w in payload["warnings"])
    assert "from config" not in output.err


def test_broken_global_config_warning_is_mirrored_in_json(
    launch_env, capsys, monkeypatch, tmp_path
):
    _, _, state = launch_env
    state["ready"] = True
    global_dir = tmp_path / "global"
    global_dir.mkdir()
    (global_dir / "config.toml").write_text("[machine]\nmemroy = \"2G\"\n")
    monkeypatch.setenv("QMU_CONFIG_DIR", str(global_dir))

    rc = cli.main(["launch", "--format", "json"])
    output = capsys.readouterr()
    payload = json.loads(output.out)

    assert rc == 0
    assert any(
        "ignoring global config" in w and "memroy" in w for w in payload["warnings"]
    )
    assert "ignoring global config" in output.err


# ---------------------------------------------------------------------------
# Arch vs cmdline lint: every built-in profile is x86; on an ARM virt guest
# `console=ttyS0 root=/dev/sda` boots a kernel that prints nothing.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("arch", ["aarch64", "arm"])
def test_x86_profile_on_an_arm_guest_warns_about_console_and_root(
    launch_env, capsys, arch
):
    _, _, state = launch_env
    state["ready"] = True

    rc = cli.main(["launch", "--arch", arch, "--format", "json"])
    output = capsys.readouterr()
    payload = json.loads(output.out)

    assert rc == 0
    warnings = payload["warnings"]
    assert any("console=ttyS0" in w and "ttyAMA0" in w for w in warnings)
    assert any("root=/dev/sda" in w and "/dev/vda" in w for w in warnings)
    assert "ttyAMA0" in output.err and "/dev/vda" in output.err


def test_arm_cmdline_with_the_right_devices_does_not_warn(launch_env, capsys):
    _, _, state = launch_env
    state["ready"] = True

    rc = cli.main([
        "launch", "--arch", "aarch64", "--format", "json",
        "--cmdline", "console=ttyAMA0 root=/dev/vda rw",
    ])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["warnings"] == []


def test_explicit_drive_suppresses_the_root_device_lint(launch_env, capsys):
    """With --drive the disk topology is the caller's; only console= is checked."""
    _, _, state = launch_env
    state["ready"] = True

    rc = cli.main([
        "launch", "--arch", "aarch64", "--format", "json",
        "--drive", "file=/tmp/x.img,if=scsi",
    ])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert not any("root=/dev/sda" in w for w in payload["warnings"])
    assert any("ttyAMA0" in w for w in payload["warnings"])


def test_arm_console_on_x86_warns(launch_env, capsys):
    _, _, state = launch_env
    state["ready"] = True

    rc = cli.main([
        "launch", "--arch", "x86_64", "--format", "json",
        "--cmdline", "console=ttyAMA0 root=/dev/sda rw",
    ])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert any("console=ttyAMA0" in w and "ttyS0" in w for w in payload["warnings"])


def test_no_reboot_flag_reaches_launch_vm(launch_env, capsys, monkeypatch):
    """`--no-reboot` lands on the resolved config (`[machine] no_reboot`),
    which is where build_qemu_command reads it (#76)."""
    seen: dict = {}
    inst, _, state = launch_env
    state["ready"] = True

    def launch(**kwargs):
        seen.update(kwargs)
        inst.harness = kwargs["harness"]
        save_instance(inst)
        return inst

    monkeypatch.setattr(lifecycle, "launch_vm", launch)

    assert cli.main(["launch", "--no-reboot", "--format", "json"]) == 0
    assert seen["config"].no_reboot is True
    assert cli.main(["launch", "--format", "json"]) == 0
    assert seen["config"].no_reboot is False

# ---------------------------------------------------------------------------
# `--vm` is accepted on launch as an alias for --name. Two different names
# silently launched the --name one and ignored the other.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_conflicting_name_and_vm_are_rejected_before_anything_runs(
    launch_env, capsys, monkeypatch, output_format
):
    monkeypatch.setattr(
        lifecycle, "launch_vm",
        lambda **kw: pytest.fail("launched despite conflicting selectors"),
    )

    rc = cli.main([
        "launch", "--name", "alpha", "--vm", "beta", "--no-wait-ssh",
        "--format", output_format,
    ])
    captured = capsys.readouterr()

    assert rc == 1
    message = captured.err if output_format == "text" else captured.out
    assert "alpha" in message and "beta" in message
    assert "--vm is an alias for --name" in message


@pytest.mark.parametrize("argv", [
    ["--name", "same", "--vm", "same"],
    ["--vm", "same"],
])
def test_matching_or_lone_vm_selector_still_names_the_launch(
    launch_env, capsys, monkeypatch, argv
):
    inst, _, state = launch_env
    state["ready"] = True
    seen = {}

    def launch(**kwargs):
        seen.update(kwargs)
        return inst

    monkeypatch.setattr(lifecycle, "launch_vm", launch)

    rc = cli.main(["launch", *argv, "--format", "json"])

    assert rc == 0
    assert seen["name"] == "same"


@pytest.mark.parametrize("output_format", ["json", "text"])
def test_launch_mirrors_the_qmp_retry_note_into_warnings(
    launch_env, capsys, monkeypatch, output_format
):
    """#76: the first-QMP-connect retry is reported, not silently absorbed —
    `warnings[]` in JSON, a `[qmu]` stderr line in text."""
    inst, _, state = launch_env
    state["ready"] = True

    def launch(**kwargs):
        kwargs["notes"].append("QMP connect retried 2× (ECONNRESET)")
        save_instance(inst)
        return inst

    monkeypatch.setattr(lifecycle, "launch_vm", launch)
    rc = cli.main(["launch", "--format", output_format])
    output = capsys.readouterr()
    assert rc == 0
    assert "[qmu] QMP connect retried 2× (ECONNRESET)" in output.err
    if output_format == "json":
        assert json.loads(output.out)["warnings"] == ["QMP connect retried 2× (ECONNRESET)"]
