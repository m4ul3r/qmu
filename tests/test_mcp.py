"""The MCP façade (#70): argparse leaves as tools, the CLI envelope as the result.

Everything here runs in-process over the SDK's memory transport
(`mcp.Client(server)`), with the daemon off (the autouse fixture), so what is
pinned is the façade's own contract: tool derivation from the real parser,
kwargs -> argv, the envelope + `qmu_exit` rule, errors as results, the two
resources, and the progress relay.
"""

from __future__ import annotations

import argparse
import json

import anyio
from mcp import Client

from qmu import daemon_client, mcp_server
from qmu._cliutil import Result
from qmu.cli import build_parser
from qmu.commands import lifecycle
from qmu.version import VERSION


def run(coro_fn):
    """Drive one client session against a fresh server; `coro_fn(client)`."""

    async def main():
        async with Client(mcp_server.build_server()) as client:
            return await coro_fn(client)

    return anyio.run(main)


def _tools():
    return run(lambda c: c.list_tools())


# --- derivation -------------------------------------------------------------


def test_tool_list_contains_the_expected_tools():
    names = {t.name for t in _tools().tools}
    for name in ("qmu_version", "qmu_status", "qmu_exec", "qmu_snapshot_save", "qmu_argv"):
        assert name in names, name
    # Excluded on purpose: the server itself, the foreground daemon, host
    # mutation, an interactive shell.
    for name in ("qmu_mcp_serve", "qmu_daemon_run", "qmu_skill_install", "qmu_rootfs_shell"):
        assert name not in names, name


def _leaves(parser, path=()):
    subs = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    if not subs:
        yield path, parser
        return
    for action in subs:
        seen = set()
        for name, sub in action.choices.items():
            if id(sub) in seen:
                continue
            seen.add(id(sub))
            yield from _leaves(sub, path + (name,))


def _leaf_paths(parser):
    return (path for path, _ in _leaves(parser))


def test_every_argparse_leaf_has_a_tool():
    """Walk the real parser independently of the façade: a new subcommand is
    a new tool, or this fails — it can never be forgotten."""
    expected = {
        "qmu_" + "_".join(path)
        for path in _leaf_paths(build_parser())
        if path and not mcp_server._excluded(path)
    }
    names = {t.name for t in _tools().tools}
    assert names == expected | {"qmu_argv"}


def test_exec_schema_requires_command_and_types_timeout_as_number():
    tool = next(t for t in _tools().tools if t.name == "qmu_exec")
    schema = tool.input_schema
    assert schema["required"] == ["command"]
    assert schema["properties"]["timeout"]["type"] == "number"
    assert "format" not in schema["properties"] and "out" not in schema["properties"]
    assert schema["properties"]["vm"]["type"] == "string"
    # One sentence, from the argparse help.
    assert tool.description == "Run command in guest"


def test_schema_maps_flags_choices_and_repeatables():
    by_name = {t.name: t for t in _tools().tools}
    launch = by_name["qmu_launch"].input_schema["properties"]
    assert launch["no_replace"] == {"type": "boolean", "description": "Don't kill existing VM with same name (default: replace)"}
    assert launch["net_backend"]["enum"] == ["user", "passt"]
    assert launch["injects"]["type"] == "array"
    assert launch["cpus"]["type"] == "integer"
    assert "required" not in by_name["qmu_launch"].input_schema
    save = by_name["qmu_snapshot_save"].input_schema
    assert save["required"] == ["name"] and save["properties"]["name"]["type"] == "string"


def test_argv_for_keeps_the_guest_command_as_one_token():
    tools = {t.name: t for t in mcp_server.build_tools(build_parser())}
    assert mcp_server.argv_for(tools["qmu_exec"], {"command": "uname -a", "timeout": 5, "vm": "x"}) == [
        "exec", "--timeout=5", "--vm=x", "--", "uname -a",
    ]
    assert mcp_server.argv_for(tools["qmu_launch"], {
        "name": "v", "no_replace": True, "gdb": False, "injects": ["a:/b", "c:/d"],
    }) == ["launch", "--name=v", "--inject=a:/b", "--inject=c:/d", "--no-replace"]
    assert mcp_server.argv_for(tools["qmu_rootfs_ls"], {"image": "r.img", "path": "/root"}) == [
        "rootfs", "ls", "--", "r.img", "/root",
    ]


def test_argv_for_encodes_dash_leading_option_values(tmp_path):
    """#125: `--qemu-arg=-M` is one token, so the value is never read as a flag."""
    tools = {t.name: t for t in mcp_server.build_tools(build_parser())}
    argv = mcp_server.argv_for(tools["qmu_run"], {"extra": ["-M", "pc"], "command": "true"})
    assert argv == ["run", "--qemu-arg=-M", "--qemu-arg=pc", "--", "true"]
    args = build_parser().parse_args(argv)
    assert args.extra == ["-M", "pc"] and args.command == ["true"]
    env = _call("qmu_run", {
        "name": "x", "no_replace": True, "kernel": str(tmp_path / "missing-bzImage"),
        "command": "true", "extra": ["-M", "pc"],
    }).structured_content
    assert env["qmu_exit"] == 1 and env["error_type"] != "UsageError", env


def test_required_sets_match_the_parser_for_every_tool():
    """#124: `required` covers required options (`kbase --symbols`), not only
    positionals, for every tool."""
    by_name = {t.name: t.input_schema for t in _tools().tools}
    checked = 0
    for path, leaf in _leaves(build_parser()):
        name = "qmu_" + "_".join(path)
        if name not in by_name:
            continue
        expected = [
            a.dest for a in leaf._actions
            if not isinstance(a, argparse._HelpAction) and a.help != argparse.SUPPRESS
            and (a.required if a.option_strings else a.nargs not in ("?", "*"))
        ]
        assert by_name[name].get("required", []) == expected, name
        checked += 1
    assert checked > 30
    assert by_name["qmu_kbase"]["required"] == ["symbols"]


def test_schema_cost_stays_under_budget():
    cost = mcp_server.schema_cost()
    assert cost["tools"] == len(_tools().tools)
    assert cost["tokens"] < 12_000, cost


# --- calls ------------------------------------------------------------------


def _call(name, arguments=None, progress_callback=None):
    return run(lambda c: c.call_tool(name, arguments or {}, progress_callback=progress_callback))


def test_version_returns_the_envelope_with_exit_code():
    result = _call("qmu_version")
    assert result.is_error is False
    assert result.structured_content == {"ok": True, "version": VERSION, "qmu_exit": 0}
    assert result.content[0].text.startswith("ok=true qmu_exit=0\n")


def test_operational_error_is_a_result_not_a_protocol_error():
    result = _call("qmu_status", {"vm": "nope"})
    env = result.structured_content
    assert result.is_error is True
    assert env["ok"] is False and env["qmu_exit"] == 1
    assert env["error_type"] == "QMUError"
    assert env["error"] and env["hint"]
    assert "QMUError" in result.content[0].text and "hint:" in result.content[0].text


def test_argv_bad_flag_is_a_usage_error_result():
    env = _call("qmu_argv", {"argv": ["status", "--bogus"]}).structured_content
    assert env["ok"] is False
    assert env["error_type"] == "UsageError"
    assert env["qmu_exit"] == 2
    assert "unrecognized arguments: --bogus" in env["error"]
    assert env["hint"] == "qmu status --help"
    assert env["usage"].startswith("usage: qmu")


def test_argv_managed_options_are_forced_after_parsing(tmp_path):
    """#123: `--format`/`--out` are overridden on the parsed namespace, so
    argparse abbreviations cannot switch the renderer or write a file."""
    out = tmp_path / "bypass.txt"
    for argv in (
        ["version", "--format", "text"],
        ["version", "--for=text"],
        ["version", "--ou", str(out)],
        ["version", "--out=" + str(out)],
    ):
        env = _call("qmu_argv", {"argv": argv}).structured_content
        assert env == {"ok": True, "version": VERSION, "qmu_exit": 0}, argv
    assert not out.exists()


def test_argv_abbreviations_of_other_options_still_work():
    short = _call("qmu_argv", {"argv": ["status", "--v", "nope"]}).structured_content
    full = _call("qmu_argv", {"argv": ["status", "--vm", "nope"]}).structured_content
    assert short == full and short["error_type"] == "QMUError" and short["qmu_exit"] == 1


def test_argv_help_is_a_success_with_stdout_and_no_error_fields():
    """#126: `--help` exits 0 with text; that is a success, not a NoEnvelope error."""
    env = _call("qmu_argv", {"argv": ["--help"]}).structured_content
    assert set(env) == {"ok", "qmu_exit", "stdout"}
    assert env["ok"] is True and env["qmu_exit"] == 0
    assert env["stdout"].startswith("usage: qmu")


def test_non_envelope_nonzero_output_keeps_the_error_fallback():
    env = mcp_server.envelope_from("garbage\n", 4, ["x"])
    assert env["ok"] is False and env["qmu_exit"] == 4
    assert env["error_type"] == "NoEnvelope" and env["stdout"] == "garbage\n"
    assert "exit_code" not in env
    env = mcp_server.envelope_from("", 2, ["x"])
    assert env["error_type"] == "UsageError" and "stdout" not in env


def test_guest_exit_code_is_never_overwritten(monkeypatch):
    """#122: `exit_code` is the guest command's (37 here, null on a guest
    timeout); the qmu process code rides separately as `qmu_exit`."""
    from qmu.commands import guest

    def fake_exec(args):
        return Result(data={"ok": False, "exit_code": 37, "stdout": "x"}, text="x", exit_code=1)

    monkeypatch.setattr(guest, "_handle_exec", fake_exec)
    env = _call("qmu_exec", {"vm": "v", "command": "exit 37"}).structured_content
    assert env["exit_code"] == 37 and env["qmu_exit"] == 1 and env["ok"] is False

    def fake_timeout(args):
        return Result(data={"ok": False, "exit_code": None, "timed_out": True}, text="x", exit_code=124)

    monkeypatch.setattr(guest, "_handle_exec", fake_timeout)
    env = _call("qmu_exec", {"vm": "v", "command": "sleep 9"}).structured_content
    assert env["exit_code"] is None and env["timed_out"] is True and env["qmu_exit"] == 124


def test_argv_group_without_subcommand_is_a_usage_error():
    env = _call("qmu_argv", {"argv": ["snapshot"]}).structured_content
    assert env["ok"] is False and env["qmu_exit"] == 2
    assert env["error_type"] == "UsageError"


def test_unknown_tool_is_a_usage_error_result():
    env = _call("qmu_nope").structured_content
    assert env["error_type"] == "UsageError" and env["qmu_exit"] == 2


def test_version_via_argv_matches_the_tool():
    assert _call("qmu_argv", {"argv": ["version"]}).structured_content == _call("qmu_version").structured_content


# --- resources --------------------------------------------------------------


def test_vms_resource_is_the_list_envelope():
    result = run(lambda c: c.read_resource("qmu://vms"))
    env = json.loads(result.contents[0].text)
    assert env == {"ok": True, "vms": [], "qmu_exit": 0}
    assert result.contents[0].mime_type == "application/json"


def test_vm_log_resource_routes_through_the_log_handler():
    env = json.loads(run(lambda c: c.read_resource("qmu://vm/nope/log")).contents[0].text)
    assert env["ok"] is False and env["error_type"] == "QMUError" and env["qmu_exit"] == 1
    assert "'nope' not found" in env["error"]


def test_resource_listing():
    resources = run(lambda c: c.list_resources()).resources
    templates = run(lambda c: c.list_resource_templates()).resource_templates
    assert [r.uri for r in resources] == ["qmu://vms"]
    assert [t.uri_template for t in templates] == ["qmu://vm/{vm_id}/log"]


# --- progress ---------------------------------------------------------------


def test_progress_sink_is_a_noop_without_a_caller():
    daemon_client.report_progress(1.0, 2, "nothing listens")  # must not raise


def test_wait_progress_reaches_the_mcp_client(monkeypatch):
    """The handler calls `daemon_client.report_progress` (as the daemon-backed
    wait does on each daemon `progress` event); the façade relays each call
    as a `notifications/progress` to the client that supplied a token."""

    def fake_wait(args):
        daemon_client.report_progress(0.5, 100, "waiting on v")
        daemon_client.report_progress(1.5, 250, "waiting on v")
        return Result(data={"ok": True, "vm_id": "v", "stopped": False}, text=["x"], stem="wait")

    monkeypatch.setattr(lifecycle, "_handle_wait", fake_wait)
    seen = []

    async def on_progress(progress, total, message):
        seen.append((progress, total, message))

    env = _call("qmu_wait", {"vm": "v", "timeout": 1}, progress_callback=on_progress).structured_content
    assert env == {"ok": True, "vm_id": "v", "stopped": False, "qmu_exit": 0}
    assert seen == [
        (0.5, None, "waiting on v (100 B scanned)"),
        (1.5, None, "waiting on v (250 B scanned)"),
    ]


def test_daemon_wait_request_forwards_progress_events(monkeypatch):
    """The client-side daemon wait path: a streamed `progress` event becomes
    a sink call with (elapsed, scanned, note); a QMP event is relayed too."""

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            pass

        def request(self, op, *, budget, on_event, **params):
            assert op == "wait" and params["vm_id"] == "v"
            on_event({"kind": "progress", "elapsed": 2.0, "scanned": 4096})
            on_event({"kind": "qmp_event", "name": "STOP", "data": None, "boot_offset": 10})
            return {"stopped": True, "reason": "process_exited", "elapsed": 2.5}

    monkeypatch.setattr(daemon_client, "connect", lambda: FakeConn())
    monkeypatch.setattr(lifecycle, "debug_session_present", lambda inst: False)
    calls = []
    token = daemon_client.progress_sink.set(lambda e, s, n: calls.append((e, s, n)))
    try:
        inst = argparse.Namespace(vm_id="v")
        args = argparse.Namespace(timeout=None, ignore_crash=False)
        reply = lifecycle._daemon_wait_request(args, inst)
    finally:
        daemon_client.progress_sink.reset(token)
    assert reply["reason"] == "process_exited"
    assert calls[0] == (2.0, 4096, "waiting on v")
    assert calls[1][1:] == (10, "QMP STOP on v")


def test_serve_subcommand_parses():
    args = build_parser().parse_args(["mcp", "serve"])
    assert args.subcommand == "mcp" and args.mcp_op == "serve"
