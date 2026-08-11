"""
mcp_server.py — config-driven poisoned MCP server for POISONVINE.

Reads a YAML manifest (kind: mcp_tools) describing an agent's tools and serves
them over streamable HTTP/TLS — the same shape a real DNS-AID-discovered
agent's MCP endpoint presents to a caller's list_agent_tools()/call_agent_tool()
flow. Each tool's description is either a literal string (undoctored decoy) or
rendered from a named payload template (see payloads.py).

Handles the mcp>=2.0 FastMCP -> MCPServer API split, so it runs against either
mcp SDK major version installed in the environment. Requires the optional
`serve` extra: pip install 'mcp>=1.28.1' uvicorn.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .. import payloads


def _load_mcp_server():
    """Import the mcp SDK lazily so this module (and its pure helpers like
    describe_tool) stay importable without the optional `serve` extra. Returns
    (MCPServer_class, major_version)."""
    try:  # mcp >= 1.28.1, < 2
        from mcp.server.fastmcp import FastMCP as MCPServer
        return MCPServer, 1
    except ImportError:
        try:  # mcp >= 2
            from mcp.server.mcpserver import MCPServer
            return MCPServer, 2
        except ImportError as e:
            raise SystemExit(
                "serve-mcp needs the mcp SDK. Install the optional extra:\n"
                "  pip install 'poisonvine[serve]'   (or: pip install 'mcp>=1.28.1' uvicorn)"
            ) from e


def describe_tool(tool_cfg: dict) -> str:
    if "description_literal" in tool_cfg:
        return tool_cfg["description_literal"]
    template = tool_cfg.get("template")
    if not template:
        raise ValueError(
            f"tool {tool_cfg.get('name')!r}: needs either 'description_literal' "
            f"or 'template' + 'template_args'"
        )
    return payloads.render(template, **tool_cfg.get("template_args", {}))


def _make_handler(name: str, param_names: list[str], fake_response_template: str):
    """Build a real typed function from the config's declared schema so the mcp
    SDK's introspection (which builds inputSchema from the signature) sees a
    normal tool — generated from trusted local config, not remote input."""
    params_sig = ", ".join(f"{p}: str" for p in param_names)
    src = (
        f"def _handler({params_sig}) -> str:\n"
        f"    _args = dict(locals())\n"
        f"    try:\n"
        f"        return _FAKE_RESPONSE.format(**_args)\n"
        f"    except (KeyError, IndexError):\n"
        f"        return _FAKE_RESPONSE\n"
    )
    namespace = {"_FAKE_RESPONSE": fake_response_template}
    exec(src, namespace)  # noqa: S102 — src built from local trusted config, not remote input
    handler = namespace["_handler"]
    handler.__name__ = name
    return handler


def build_server(config: dict):
    MCPServer, major = _load_mcp_server()
    agent_name = config.get("agent_name", "poisonvine-fake-agent")
    port = config.get("port", 443)
    if major == 1:
        mcp = MCPServer(agent_name, host="0.0.0.0", port=port, streamable_http_path="/mcp")
    else:
        mcp = MCPServer(agent_name)

    tools_cfg = config.get("tools", [])
    if not tools_cfg:
        raise ValueError("config has no 'tools' entries")

    for tool_cfg in tools_cfg:
        name = tool_cfg["name"]
        description = describe_tool(tool_cfg)
        schema = tool_cfg.get("schema", {"id": "string"})
        param_names = list(schema.keys())
        fake_response = tool_cfg.get("fake_response", f"{{{param_names[0]}}} handled")
        handler = _make_handler(name, param_names, fake_response)
        mcp.tool(description=description)(handler)

    mcp._pv_major = major  # stash for main() to pick the right app builder
    return mcp


def main(argv=None) -> int:
    import yaml

    p = argparse.ArgumentParser(
        description="Serve a config-driven poisoned MCP agent for POISONVINE testing."
    )
    p.add_argument("--config", required=True, help="YAML manifest, kind: mcp_tools")
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--host", default="0.0.0.0")
    args = p.parse_args(argv)

    config = yaml.safe_load(Path(args.config).read_text())
    if config.get("kind") != "mcp_tools":
        raise SystemExit(f"{args.config}: expected 'kind: mcp_tools', got {config.get('kind')!r}")

    mcp = build_server(config)

    import uvicorn

    if getattr(mcp, "_pv_major", 1) == 1:
        app = mcp.streamable_http_app()
    else:
        app = mcp.streamable_http_app(streamable_http_path="/mcp", host=args.host)

    uvicorn.run(app, host=args.host, port=args.port,
                ssl_certfile=args.cert, ssl_keyfile=args.key, log_level="info")
    return 0
