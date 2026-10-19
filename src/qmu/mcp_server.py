"""MCP façade over the CLI (#70): every argparse leaf as a tool, nothing else.

The façade is a *renderer substitute*, not a second command layer. A tool
call becomes an argv (`qmu --format json <group> <sub> --flag value -- POS`),
runs through the real parser and :func:`qmu.cli.run_parsed` with stdout
captured, and hands back the JSON envelope the CLI would have printed, plus
``qmu_exit`` — the qmu process exit code (MCP has no exit codes). That is
the whole contract:

- the tool list is derived from :func:`qmu.cli.build_parser` at startup —
  the same ``_add_*`` registrars the CLI uses, so a new subcommand is a new
  tool with no edit here (``tests/test_mcp.py`` walks the parser to prove it);
- the envelope is byte-for-byte the CLI's ``--format json`` output: the
  ``ok``/``error``/``error_type``/``hint``/``warnings[]`` keys, the spill
  pointer when a result is large, the ``UsageError`` envelope for a bad
  argument — because it IS that output, parsed back;
- the exit-code contract (``cli.py`` epilog) rides as ``qmu_exit``; domain
  keys are never touched, so ``exit_code`` stays the GUEST command's code
  (``exec``/``run``) exactly as the CLI reports it (#122); errors are
  results, never protocol errors, so an agent branches on ``ok`` exactly as
  it does on the CLI.

``qmu_argv`` passes a raw argv through for anything the derived tools do not
express (or for agents that already know the CLI from the skill). Two
resources read via the same path: ``qmu://vms`` (the ``list`` envelope) and
``qmu://vm/{vm_id}/log`` (``log --tail 200``).

Progress: a tool call runs in a worker thread with
:data:`qmu.daemon_client.progress_sink` set, so the daemon-backed ``wait``
relays its ``progress`` events to the MCP client as ``notifications/progress``
(``progress`` = elapsed seconds, ``message`` = note + scanned bytes).
Without the daemon there is nothing to relay and the sink is simply never
called.

Excluded leaves: ``mcp serve`` itself, ``daemon run`` (the foreground
server), ``skill install`` (host mutation) and ``rootfs shell`` (an
interactive guestfish session has no meaning over a request/response wire).
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from . import daemon_client
from .version import VERSION

SERVER_NAME = "qmu"
LOG_RESOURCE_TAIL = 200

# (path prefixes) whose leaves are not exposed; see the module docstring.
EXCLUDED: frozenset[tuple[str, ...]] = frozenset({
    ("mcp",), ("daemon", "run"), ("skill", "install"), ("rootfs", "shell"),
})
# Options the façade owns: it always runs `--format json` and never writes a
# file. Enforced on the parsed namespace (see `call_cli`), so abbreviations
# argparse accepts (`--for=text`, `--ou PATH`) cannot bypass it (#123).
OMITTED_OPTIONS = frozenset({"format", "out"})
MANAGED_VALUES: dict[str, Any] = {"format": "json", "out": None}

# Tool/argument descriptions are the first sentence of the argparse help:
# the full help lives in `qmu <sub> --help` and the skill, and the listing is
# paid for on every session (see `schema_cost`). A sentence ends at a `.`/`;`
# followed by whitespace (or the end), outside parentheses, and not closing
# an abbreviation (#131: splitting on every `.` cut "e.g." examples off).
_ABBREVIATIONS = frozenset({"e.g", "i.e", "cf", "etc", "vs", "approx"})

ProgressFn = Callable[[float, int, str], None]


# ---------------------------------------------------------------------------
# Tool derivation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolSpec:
    """One exposed leaf: its argv path, JSON schema and the actions behind it."""

    name: str
    path: tuple[str, ...]
    description: str
    positionals: tuple[argparse.Action, ...]
    options: tuple[argparse.Action, ...]
    schema: dict[str, Any] = field(default_factory=dict)


def first_sentence(text: str | None) -> str:
    text = " ".join((text or "").split())
    depth = 0
    for i, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(depth - 1, 0)
        elif ch in ".;" and depth == 0 and (i + 1 == len(text) or text[i + 1] == " "):
            word = text[:i].rsplit(" ", 1)[-1].lstrip("(\"'`").lower()
            if ch == "." and word in _ABBREVIATIONS:
                continue
            return text[: i + 1].rstrip(";")
    return text.rstrip(";")


def _iter_leaves(
    parser: argparse.ArgumentParser, path: tuple[str, ...] = (), help_text: str | None = None
):
    """Yield (path, leaf parser, help) depth-first, one entry per parser object
    (an alias such as `status`/`show` shares one parser and appears once)."""
    subs = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    if not subs:
        yield path, parser, help_text
        return
    for action in subs:
        helps = {c.dest: c.help for c in action._choices_actions}
        seen: set[int] = set()
        for name, sub in action.choices.items():
            if id(sub) in seen:
                continue
            seen.add(id(sub))
            yield from _iter_leaves(sub, path + (name,), helps.get(name))


def _json_type(action: argparse.Action) -> dict[str, Any]:
    if isinstance(action, argparse._StoreTrueAction):
        return {"type": "boolean"}
    if action.type is int:
        return {"type": "integer"}
    if action.type is float or (callable(action.type) and "float" in getattr(action.type, "__name__", "")):
        return {"type": "number"}
    if callable(action.type) and "seconds" in getattr(action.type, "__name__", ""):
        return {"type": "number"}
    if isinstance(action, argparse._AppendAction):
        return {"type": "array", "items": {"type": "string"}}
    if action.nargs in ("+", "*"):
        # One string is ONE argv token (the `exec`/`run` guest-command rule);
        # a list is spread into several.
        return {"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]}
    return {"type": "string"}


def _property(action: argparse.Action) -> dict[str, Any]:
    prop = _json_type(action)
    if action.choices:
        prop["enum"] = list(action.choices)
    desc = first_sentence(action.help)
    if action.option_strings:
        # A property named after an argparse dest that is not its flag
        # (`cpu_model` for `--cpu`) names the flag, so a host can map it
        # back for `qmu_argv` (#131).
        flag = _long_flag(action.option_strings)
        if flag.lstrip("-").replace("-", "_") != action.dest:
            desc = f"{flag}: {desc}" if desc else flag
    if desc:
        prop["description"] = desc
    if action.default not in (None, argparse.SUPPRESS, False) and action.nargs not in ("*",):
        prop["default"] = action.default
    return prop


def _excluded(path: tuple[str, ...]) -> bool:
    return any(path[: len(prefix)] == prefix for prefix in EXCLUDED)


def build_tools(parser: argparse.ArgumentParser) -> list[ToolSpec]:
    tools: list[ToolSpec] = []
    for path, leaf, help_text in _iter_leaves(parser):
        if not path or _excluded(path) or "handler" not in leaf._defaults:
            continue
        positionals: list[argparse.Action] = []
        options: list[argparse.Action] = []
        props: dict[str, Any] = {}
        required: list[str] = []
        for action in leaf._actions:
            if isinstance(action, argparse._HelpAction) or action.help == argparse.SUPPRESS:
                continue
            if action.dest in OMITTED_OPTIONS and action.option_strings:
                continue
            props[action.dest] = _property(action)
            if action.option_strings:
                options.append(action)
                if action.required:
                    required.append(action.dest)
            else:
                positionals.append(action)
                if action.nargs not in ("?", "*"):
                    required.append(action.dest)
        schema: dict[str, Any] = {"type": "object", "properties": props, "additionalProperties": False}
        if required:
            schema["required"] = required
        tools.append(ToolSpec(
            name="qmu_" + "_".join(path),
            path=path,
            description=first_sentence(help_text or leaf.description) or f"qmu {' '.join(path)}",
            positionals=tuple(positionals),
            options=tuple(options),
            schema=schema,
        ))
    return tools


def _tokens(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _long_flag(option_strings: list[str]) -> str:
    return next((o for o in option_strings if o.startswith("--")), option_strings[0])


def argv_for(spec: ToolSpec, arguments: dict[str, Any]) -> list[str]:
    """`arguments` (validated against `spec.schema` by shape only) → argv.

    Options first, then `--`, then positionals in declaration order, so a
    positional that starts with `-` (a guest command such as `-- 'ls -la'`)
    is never read as a qmu flag. Every valued option is one `--flag=value`
    token (#125): a dash-leading value (`--qemu-arg=-M`) would otherwise be
    read as the next option. Unknown keys are passed as `--key=value` so the
    CLI's own usage error names them, rather than a façade message.
    """
    argv: list[str] = list(spec.path)
    known = {a.dest for a in spec.positionals} | {a.dest for a in spec.options}
    for action in spec.options:
        value = arguments.get(action.dest)
        if value is None:
            continue
        flag = _long_flag(action.option_strings)
        if isinstance(action, argparse._StoreTrueAction):
            if value:
                argv.append(flag)
        else:
            argv += [f"{flag}={item}" for item in _tokens(value)]
    for key, value in arguments.items():
        if key not in known and value is not None:
            flag = "--" + key.replace("_", "-")
            argv += [f"{flag}={item}" for item in _tokens(value)]
    tail: list[str] = []
    for action in spec.positionals:
        value = arguments.get(action.dest)
        if value is None:
            continue
        tail += _tokens(value)
    if tail:
        argv.append("--")
        argv += tail
    return argv


# ---------------------------------------------------------------------------
# Running the CLI in-process
# ---------------------------------------------------------------------------


class _ThreadStdout:
    """`sys.stdout` replacement: each worker thread captures into its own
    buffer; threads not capturing fall through to the original stream (the
    stdio transport owns the real fd 1, so nothing of qmu's ever reaches the
    wire)."""

    def __init__(self, fallback: Any):
        self._fallback = fallback
        self._local = threading.local()

    def capture(self, buf: io.StringIO | None) -> None:
        self._local.buf = buf

    def _target(self) -> Any:
        return getattr(self._local, "buf", None) or self._fallback

    def write(self, s: str) -> int:
        return self._target().write(s)

    def flush(self) -> None:
        self._target().flush()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._fallback, name)


_stdout_lock = threading.Lock()


def _capturing_stdout() -> _ThreadStdout:
    with _stdout_lock:
        if not isinstance(sys.stdout, _ThreadStdout):
            sys.stdout = _ThreadStdout(sys.stdout)
        return sys.stdout


def call_cli(argv: list[str], progress: ProgressFn | None = None) -> dict[str, Any]:
    """Run `qmu --format json <argv>` in this thread; return its envelope + `qmu_exit`.

    Everything the CLI prints to stdout is captured and parsed back; stderr
    is left alone (the host shows it as server log). A usage error's
    ``SystemExit(2)`` is caught after the CLI wrote its ``UsageError``
    envelope, so it comes back as a result too.

    The managed options are enforced on the PARSED namespace, not by
    inspecting argv (#123): argparse accepts abbreviations (``--for=text``,
    ``--ou PATH``), so no spelling of ``--format``/``--out`` can switch the
    renderer or write a file — ``args.format`` is forced to ``json`` and
    ``args.out`` to ``None`` before anything is dispatched or rendered.
    """
    from . import cli  # local: the CLI imports every command module

    if progress is not None:
        daemon_client.progress_sink.set(progress)
    out = _capturing_stdout()
    buf = io.StringIO()
    out.capture(buf)
    try:
        try:
            args = cli._parse(["--format", "json", *argv])
            if args is None:
                code = 2
            else:
                for dest in OMITTED_OPTIONS:
                    setattr(args, dest, MANAGED_VALUES[dest])
                code = cli.run_parsed(args)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    finally:
        out.capture(None)
    return envelope_from(buf.getvalue(), code, argv)


def envelope_from(stdout: str, code: int, argv: list[str]) -> dict[str, Any]:
    """The CLI's envelope with the qmu process exit code under ``qmu_exit``.

    Domain keys are never touched: ``exit_code`` stays the guest command's
    code (``exec``/``run``), and is absent where the CLI has none (#122).

    Output that is not an envelope — ``--help`` text, a group's help, a
    silent handler — is only reachable through ``qmu_argv``. With exit 0 it
    is a success carrying ``stdout`` and no error fields (#126); otherwise
    the error-shaped fallback names the argv and the code.
    """
    text = stdout.strip()
    try:
        data = json.loads(text) if text else None
    except ValueError:
        data = None
    if isinstance(data, dict):
        return {**data, "qmu_exit": code}
    if code == 0:
        return {"ok": True, "qmu_exit": 0, "stdout": stdout}
    data = {
        "ok": False,
        "error": f"`qmu {' '.join(argv)}` produced no JSON envelope (exit {code})",
        "error_type": "UsageError" if code == 2 else "NoEnvelope",
        "hint": "qmu --help",
        "qmu_exit": code,
    }
    if text:
        data["stdout"] = stdout
    return data


def usage_error(message: str, hint: str) -> dict[str, Any]:
    return {"ok": False, "error": message, "error_type": "UsageError", "hint": hint, "qmu_exit": 2}


def summary_text(envelope: dict[str, Any]) -> str:
    """The compact text block beside the structured result: status line, then
    the envelope minus its bulkiest member, for hosts that show text only."""
    ok = envelope.get("ok")
    head = f"ok={str(ok).lower()} qmu_exit={envelope.get('qmu_exit')}"
    if not ok and envelope.get("error"):
        head += f" {envelope.get('error_type', 'Error')}: {envelope['error']}"
        if envelope.get("hint"):
            head += f"\nhint: {envelope['hint']}"
    body = json.dumps(envelope, indent=None, separators=(",", ":"), default=str)
    return f"{head}\n{body}"


# ---------------------------------------------------------------------------
# The server
# ---------------------------------------------------------------------------


ARGV_TOOL = "qmu_argv"
ARGV_SCHEMA = {
    "type": "object",
    "properties": {
        "argv": {
            "type": "array",
            "items": {"type": "string"},
            "description": "qmu arguments exactly as on the command line, without the leading `qmu`",
        }
    },
    "required": ["argv"],
    "additionalProperties": False,
}


def tool_listing(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    """The `tools/list` payload as plain dicts (also what the schema-cost
    measurement serialises)."""
    listing = [
        {"name": t.name, "description": t.description, "inputSchema": t.schema} for t in tools
    ]
    listing.append({
        "name": ARGV_TOOL,
        "description": "Run any qmu command from a raw argv; same envelope + qmu_exit as the other tools (--format/--out are managed and overridden).",
        "inputSchema": ARGV_SCHEMA,
    })
    return listing


def build_server():
    """A lowlevel `mcp.server.Server` wired to the derived tools and resources."""
    import anyio
    from mcp import types
    from mcp.server import Server

    from .cli import build_parser

    tools = build_tools(build_parser())
    by_name = {t.name: t for t in tools}
    listing = tool_listing(tools)

    def sink_for(ctx) -> ProgressFn:
        def sink(elapsed: float, scanned: int, note: str) -> None:
            try:
                anyio.from_thread.run(
                    ctx.session.report_progress, elapsed, None, f"{note} ({scanned} B scanned)"
                )
            except Exception:  # noqa: BLE001 — progress is best-effort
                pass
        return sink

    async def run_tool(ctx, argv: list[str]) -> types.CallToolResult:
        envelope = await anyio.to_thread.run_sync(call_cli, argv, sink_for(ctx))
        return _result(envelope)

    def _result(envelope: dict[str, Any]) -> types.CallToolResult:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=summary_text(envelope))],
            structured_content=envelope,
            is_error=not bool(envelope.get("ok")),
        )

    async def on_list_tools(ctx, params):
        return types.ListToolsResult(tools=[types.Tool(**item) for item in listing])

    async def on_call_tool(ctx, params: types.CallToolRequestParams):
        arguments = dict(params.arguments or {})
        if params.name == ARGV_TOOL:
            return await run_tool(ctx, [str(a) for a in arguments.get("argv") or []])
        spec = by_name.get(params.name)
        if spec is None:
            return _result(usage_error(
                f"unknown tool {params.name!r}", "tools/list names every qmu subcommand as qmu_<sub>"
            ))
        return await run_tool(ctx, argv_for(spec, arguments))

    async def on_list_resources(ctx, params):
        return types.ListResourcesResult(resources=[
            types.Resource(
                uri="qmu://vms", name="vms", mime_type="application/json",
                description="Every VM qmu knows about (the `qmu list` envelope)",
            ),
        ])

    async def on_list_resource_templates(ctx, params):
        return types.ListResourceTemplatesResult(resource_templates=[
            types.ResourceTemplate(
                uri_template="qmu://vm/{vm_id}/log", name="vm-log", mime_type="application/json",
                description=f"Last {LOG_RESOURCE_TAIL} serial-console lines of one VM (`qmu log --tail`)",
            ),
        ])

    async def on_read_resource(ctx, params: types.ReadResourceRequestParams):
        uri = params.uri
        if uri == "qmu://vms":
            argv = ["list"]
        else:
            m = re.fullmatch(r"qmu://vm/([^/]+)/log", uri)
            if m is None:
                envelope = usage_error(
                    f"unknown resource {uri!r}", "resources: qmu://vms, qmu://vm/{vm_id}/log"
                )
                return types.ReadResourceResult(contents=[types.TextResourceContents(
                    uri=uri, mime_type="application/json", text=json.dumps(envelope),
                )])
            argv = ["log", "--vm", m.group(1), "--tail", str(LOG_RESOURCE_TAIL)]
        envelope = await anyio.to_thread.run_sync(call_cli, argv, None)
        return types.ReadResourceResult(contents=[types.TextResourceContents(
            uri=uri, mime_type="application/json", text=json.dumps(envelope),
        )])

    return Server(
        SERVER_NAME,
        version=VERSION,
        instructions=(
            "Each tool is one qmu subcommand (qmu_<group>_<sub>) and returns the CLI's "
            "JSON envelope with qmu_exit (the qmu process exit code) added; exit_code is "
            "the guest command's own code. Branch on ok/qmu_exit, never on "
            "transport errors. qmu_argv runs a raw argv. The qmu skill documents the "
            "commands and the envelope."
        ),
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
        on_list_resources=on_list_resources,
        on_list_resource_templates=on_list_resource_templates,
        on_read_resource=on_read_resource,
    )


async def serve_stdio() -> None:
    from mcp.server.stdio import stdio_server

    server = build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def schema_cost(tools: list[ToolSpec] | None = None) -> dict[str, int]:
    """Serialised `tools/list` size: chars and the chars/4 token estimate."""
    if tools is None:
        from .cli import build_parser

        tools = build_tools(build_parser())
    chars = len(json.dumps(tool_listing(tools), separators=(",", ":")))
    return {"tools": len(tools) + 1, "chars": chars, "tokens": chars // 4}
