"""`qmu config show` names the layer that set every key.

Measured before this: the starter qmu.toml ships an uncommented `[ssh] key`
that silently shadowed the global config the skill tells you to put your key
in, and `config show` printed the layer CHAIN but no per-key provenance — so
`doctor` said `[!] SSH key: ~/.ssh/qmu_id_rsa` and nothing said "from the
project file". It also omitted `nic_model`/`net_backend`/`accel`, and showed
paths unresolved with no existence marker.
"""

from __future__ import annotations

import json

import pytest

from qmu import cli


@pytest.fixture
def layered(tmp_path, monkeypatch):
    global_dir = tmp_path / "global-config"
    global_dir.mkdir()
    monkeypatch.setenv("QMU_CONFIG_DIR", str(global_dir))
    gpath = global_dir / "config.toml"
    gpath.write_text(
        '[machine]\nmemory = "8G"\n[ssh]\nkey = "./global_key"\n'
    )
    (global_dir / "global_key").write_text("k")

    project = tmp_path / "proj"
    project.mkdir()
    ppath = project / "qmu.toml"
    ppath.write_text(
        '[boot]\nkernel = "./bzImage"\n[ssh]\nkey = "./project_key"\n'
        '[machine]\nnic_model = "e1000"\naccel = "tcg"\n'
    )
    (project / "bzImage").write_bytes(b"\x00")
    monkeypatch.chdir(project)
    return {"global": gpath.resolve(), "project": ppath.resolve(), "dir": project.resolve()}


def test_config_show_json_has_per_key_sources_and_resolved_paths(layered, capsys):
    rc = cli.main(["--format", "json", "config", "show"])
    data = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert data["layers"] == [
        "built-in defaults", f"global: {layered['global']}", f"project: {layered['project']}",
    ]
    sources = data["sources"]
    assert sources["boot.kernel"] == f"project {layered['project']}"
    assert sources["ssh.key"] == f"project {layered['project']}"  # shadows the global
    assert sources["machine.memory"] == f"global {layered['global']}"
    assert sources["machine.nic_model"] == f"project {layered['project']}"
    assert sources["machine.accel"] == f"project {layered['project']}"
    assert sources["machine.cpus"] == "built-in"
    assert sources["profiles.exploit-dev"] == "built-in"

    machine = data["machine"]
    assert machine["nic_model"] == "e1000"
    assert machine["net_backend"] == "user"
    assert machine["accel"] == "tcg"
    assert machine["kvm"] is False

    assert data["paths"]["boot.kernel"] == {
        "written": "./bzImage",
        "resolved": str(layered["dir"] / "bzImage"),
        "exists": True,
    }
    assert data["paths"]["ssh.key"] == {
        "written": "./project_key",
        "resolved": str(layered["dir"] / "project_key"),
        "exists": False,
    }
    assert data["paths"]["drive.rootfs"] is None
    # The raw values are still the anchored ones launch uses.
    assert data["boot"]["kernel"] == str(layered["dir"] / "bzImage")


def test_config_show_text_labels_every_row_with_its_layer(layered, capsys):
    rc = cli.main(["config", "show"])
    out = capsys.readouterr().out

    assert rc == 0
    assert f"Layers:      built-in defaults -> global: {layered['global']}" in out
    assert (
        f"Kernel:      ./bzImage -> {layered['dir'] / 'bzImage'}  "
        f"[project {layered['project']}]"
    ) in out
    assert (
        f"SSH key:     ./project_key -> {layered['dir'] / 'project_key'} (not found)  "
        f"[project {layered['project']}]"
    ) in out
    assert f"Memory:      8G  [global {layered['global']}]" in out
    assert "CPUs:        2  [built-in]" in out
    assert "NIC model:   e1000  [project" in out
    assert "Net backend: user  [built-in]" in out
    assert "Accel:       tcg (kvm=False)  [project" in out
    assert "    exploit-dev  [built-in]" in out


def test_config_show_text_and_json_agree_on_every_layer(layered, capsys):
    """Text-vs-JSON axis: the bracketed layer on each text row is the JSON
    `sources` value for that key."""
    cli.main(["--format", "json", "config", "show"])
    sources = json.loads(capsys.readouterr().out)["sources"]
    cli.main(["config", "show"])
    text = capsys.readouterr().out

    rows = {
        "boot.kernel": "Kernel:", "machine.memory": "Memory:", "machine.cpus": "CPUs:",
        "machine.accel": "Accel:", "ssh.key": "SSH key:", "ssh.user": "SSH user:",
    }
    for key, label in rows.items():
        line = next(l for l in text.splitlines() if l.strip().startswith(label))
        assert line.endswith(f"[{sources[key]}]"), (key, line)


def test_config_show_flag_layer(layered, capsys):
    rc = cli.main(["--format", "json", "config", "show", "--config", str(layered["project"])])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["sources"]["boot.kernel"] == f"--config {layered['project']}"
