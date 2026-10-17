"""`qmu mcp serve` — the MCP façade over stdio (#70).

Register once with the host (`claude mcp add qmu -- qmu mcp serve`); the
host spawns this process and talks JSON-RPC on its stdin/stdout. Everything
qmu would have printed to stdout is captured per tool call and returned as
the tool's result, so the wire never sees it; stderr is the server log.
"""

from __future__ import annotations

import argparse

from .._cliutil import Result, _add_format_opts, _make_group_help_handler


def _add_mcp(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "mcp",
        help="Serve qmu's commands as MCP tools (one per subcommand) over stdio",
        description=(
            "Expose every qmu subcommand as an MCP tool named qmu_<sub> / "
            "qmu_<group>_<sub>, plus qmu_argv for a raw argv. Each tool returns "
            "the --format json envelope with exit_code added. Register with "
            "`claude mcp add qmu -- qmu mcp serve`."
        ),
    )
    p.set_defaults(handler=_make_group_help_handler(p))
    ops = p.add_subparsers(dest="mcp_op")

    serve = ops.add_parser("serve", help="Run the MCP server on stdin/stdout until the client closes")
    _add_format_opts(serve)
    serve.set_defaults(handler=_handle_mcp_serve)


def _handle_mcp_serve(args: argparse.Namespace) -> Result:
    import anyio

    from ..mcp_server import serve_stdio

    anyio.run(serve_stdio)
    return Result.silent_exit(0)
