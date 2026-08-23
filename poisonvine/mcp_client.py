"""
mcp_client.py — a real MCP client for POISONVINE.

Talks the real protocol directly — streamable-HTTP transport + a real
`mcp.ClientSession`, real `initialize()` + `list_tools()`/`call_tool()`/
`read_resource()`/`get_prompt()` — against a live MCP server (either
servers/mcp_server.py's `serve()`, or any other real endpoint). This is what
lets `pv query --live-endpoint` and campaign.py's live "content"/"rugpull"/
"shadow" techniques work standalone, with no external MCP-client dependency.

Targets the mcp>=2.0 SDK client API. Requires the optional `serve` extra:
pip install 'mcp>=1.28.1' uvicorn (or `pip install -e '.[serve]'`).
"""

from __future__ import annotations

import asyncio


async def list_tools(endpoint: str) -> list[dict]:
    """Fetch the real tools/list result from a live MCP server, over the real
    protocol. Returns [{"name", "description", "inputSchema"}, ...] — the
    same shape channels/mcp.py's _tool()/_tools_json() build for static
    transcripts, so campaign.py can treat live and replayed results the same
    way."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with streamable_http_client(endpoint) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            return [
                {
                    "name": t.name,
                    "description": t.description or "",
                    "inputSchema": t.input_schema,
                }
                for t in result.tools
            ]


async def call_tool(endpoint: str, tool_name: str, args: dict | None = None) -> dict:
    """Call a tool on a live MCP server and return its result content as
    plain text plus the raw error flag. This is how campaign.py materializes
    kind="content" techniques: the fixture serves poisoned content, and this
    function is the real client path that pulls it back into the ingested
    transcript — the same round trip a real consuming agent would make."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with streamable_http_client(endpoint) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, args or {})
            text_parts = [
                block.text for block in result.content
                if getattr(block, "type", None) == "text"
            ]
            return {"text": "\n".join(text_parts), "is_error": bool(result.is_error)}


async def list_resources(endpoint: str) -> list[dict]:
    """Real resources/list, for the resources-primitive content-poisoning
    class (same shape as tool-result poisoning, different primitive)."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with streamable_http_client(endpoint) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_resources()
            return [
                {"uri": r.uri, "name": r.name, "description": r.description or ""}
                for r in result.resources
            ]


async def read_resource(endpoint: str, uri: str) -> dict:
    """Real resources/read — the resource-primitive equivalent of call_tool()
    for materializing a kind='content' technique."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with streamable_http_client(endpoint) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.read_resource(uri)
            text_parts = [c.text for c in result.contents if hasattr(c, "text")]
            return {"text": "\n".join(text_parts)}


async def list_prompts(endpoint: str) -> list[dict]:
    """Real prompts/list, for the prompts-primitive content-poisoning class."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with streamable_http_client(endpoint) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_prompts()
            return [
                {"name": p.name, "description": p.description or ""}
                for p in result.prompts
            ]


async def get_prompt(endpoint: str, name: str, args: dict | None = None) -> dict:
    """Real prompts/get — the prompt-primitive equivalent of call_tool()."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with streamable_http_client(endpoint) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.get_prompt(name, args or {})
            text_parts = [
                m.content.text for m in result.messages
                if getattr(m.content, "type", None) == "text"
            ]
            return {"text": "\n".join(text_parts)}


def fetch_live_tools_sync(endpoint: str) -> list[dict]:
    """Sync wrapper for CLI use (pv query --live-endpoint)."""
    return asyncio.run(list_tools(endpoint))


def call_tool_sync(endpoint: str, tool_name: str, args: dict | None = None) -> dict:
    return asyncio.run(call_tool(endpoint, tool_name, args))


def read_resource_sync(endpoint: str, uri: str) -> dict:
    return asyncio.run(read_resource(endpoint, uri))


def get_prompt_sync(endpoint: str, name: str, args: dict | None = None) -> dict:
    return asyncio.run(get_prompt(endpoint, name, args))
