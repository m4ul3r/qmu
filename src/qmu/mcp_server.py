"""MCP façade over the CLI (#70): every argparse leaf as a tool, nothing else.

The façade is a *renderer substitute*, not a second command layer. A tool
call becomes an argv (`qmu --format json <group> <sub> --flag value -- POS`),
runs through :func:`qmu.cli.main` with stdout captured, and hands back the
JSON envelope the CLI would have printed, plus ``exit_code`` (MCP has no
exit codes). That is the whole contract:

- the tool list is derived from :func:`qmu.cli.build_parser` at startup —
  the same ``_add_*`` registrars the CLI uses, so a new subcommand is a new
  tool with no edit here (``tests/test_mcp.py`` walks the parser to prove it);
- the envelope is byte-for-byte the CLI's ``--format json`` output: the
  ``ok``/``error``/``error_type``/``hint``/``warnings[]`` keys, the spill
  pointer when a result is large, the ``UsageError`` envelope for a bad
  argument — because it IS that output, parsed back;
- the exit-code contract (``cli.py`` epilog) rides as ``exit_code``; errors
  are results, never protocol errors, so an agent branches on ``ok`` exactly
  as it does on the CLI.

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
# Flags the façade owns: it always runs `--format json` and never writes a file.
OMITTED_OPTIONS = frozenset({"format", "out"})

# Tool/argument descriptions are the first sentence of the argparse help:
# the full help lives in `qmu <sub> --help` and the skill, and the listing is
# paid for on every session (see `schema_cost`).
_FIRST_SENTENCE = re.compile(r"^(.*?[.;])(?:\s|$)")

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
    m = _FIRST_SENTENCE.match(text)
    return (m.group(1) if m else text).rstrip(";")


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


def argv_for(spec: ToolSpec, arguments: dict[str, Any]) -> list[str]:
    """`arguments` (validated against `spec.schema` by shape only) → argv.

    Options first, then `--`, then positionals in declaration order, so a
    positional that starts with `-` (a guest command such as `-- 'ls -la'`)
    is never read as a qmu flag. Unknown keys are passed as `--key value` so
    the CLI's own usage error names them, rather than a façade message.
    """
    argv: list[str] = list(spec.path)
    known = {a.dest for a in spec.positionals} | {a.dest for a in spec.options}
    for action in spec.options:
        value = arguments.get(action.dest)
        if value is None:
            continue
        flag = action.option_strings[0]
        if isinstance(action, argparse._StoreTrueAction):
            if value:
                argv.append(flag)
        elif isinstance(action, argparse._AppendAction):
            for item in _tokens(value):
                argv += [flag, item]
        else:
            argv += [flag, str(value)]
    for key, value in arguments.items():
        if key not in known and value is not None:
            argv += ["--" + key.replace("_", "-"), *_tokens(value)]
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
    """Run `qmu --format json <argv>` in this thread; return its envelope + `exit_code`.

    Everything the CLI prints to stdout is captured and parsed back; stderr
    is left alone (the host shows it as server log). A usage error's
    ``SystemExit(2)`` is caught after the CLI wrote its ``UsageError``
    envelope, so it comes back as a result too.
    """
    from . import cli  # local: the CLI imports every command module

    if progress is not None:
        daemon_client.progress_sink.set(progress)
    out = _capturing_stdout()
    buf = io.StringIO()
    out.capture(buf)
    try:
        try:
            code = cli.main(["--format", "json", *argv])
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    finally:
        out.capture(None)
    return envelope_from(buf.getvalue(), code, argv)


def envelope_from(stdout: str, code: int, argv: list[str]) -> dict[str, Any]:
    text = stdout.strip()
    try:
        data = json.loads(text) if text else None
    except ValueError:
        data = None
    if not isinstance(data, dict):
        # A leaf that renders nothing in json mode (a group's help, a silent
        # handler) — only reachable through `qmu_argv`.
        data = {
            "ok": code == 0,
            "error": f"`qmu {' '.join(argv)}` produced no JSON envelope (exit {code})",
            "error_type": "UsageError" if code == 2 else "NoEnvelope",
            "hint": "qmu --help",
        }
        if text:
            data["stdout"] = stdout
    return {**data, "exit_code": code}


def usage_error(message: str, hint: str) -> dict[str, Any]:
    return {"ok": False, "error": message, "error_type": "UsageError", "hint": hint, "exit_code": 2}


def summary_text(envelope: dict[str, Any]) -> str:
    """The compact text block beside the structured result: status line, then
    the envelope minus its bulkiest member, for hosts that show text only."""
    ok = envelope.get("ok")
    head = f"ok={str(ok).lower()} exit_code={envelope.get('exit_code')}"
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
        "description": "Run any qmu command from a raw argv; same envelope + exit_code as the other tools.",
        "inputSchema": ARGV_SCHEMA,
    })
    return listing


def _managed_flags(argv: list[str]) -> str | None:
    for token in argv:
        if token in ("--format", "--out") or token.startswith(("--format=", "--out=")):
            return token
        if token == "--":
            break
    return None


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
            argv = [str(a) for a in arguments.get("argv") or []]
            managed = _managed_flags(argv)
            if managed:
                return _result(usage_error(
                    f"{managed} is managed by the MCP façade (every tool runs --format json "
                    "and returns the envelope inline)", "drop the flag; large results spill "
                    "to a file and come back as a pointer envelope",
                ))
            return await run_tool(ctx, argv)
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
            "JSON envelope with exit_code added; branch on ok/exit_code, never on "
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
