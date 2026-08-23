"""
campaign.py — the POISONVINE orchestrator ("the vine").

Walks the channel registry, materializes each technique's transcript (serving a
single throwaway DNS zone and running real `dig` for the DNS/SVCB techniques,
rendering JSON/text directly for description-poisoning MCP techniques, and — for
the MCP content/rugpull/shadow techniques — standing up a real local MCP server
and doing a real client round trip via `servers/mcp_server.serve()` + `mcp_client.py`),
wraps each in its channel's prompt, sends it to the target model(s), and reports
which channels landed the marker.

The DNS/SVCB/description-poisoning path needs only dnslib + stdlib + a provider.
The MCP content/rugpull/shadow techniques need the optional `serve` extra
(`pip install -e '.[serve]'`); without it they gracefully fall back to their
static build-only transcripts instead of a live round trip. `pv serve-mcp` +
`pv query --live-endpoint` remain available as a separate, fully manual live path.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import channels as ch
from .providers import build_provider
from .servers.dns_server import DEFAULT_DNS_PORT, ZoneServer, dig

# kind values that need a live local MCP server + real client round trip
# (channels/mcp.py's CT1/RES1/PR1/RP1/SH1) rather than a static transcript.
_MCP_LIVE_KINDS = {"content", "rugpull", "shadow"}


def _mcp_sdk_available() -> bool:
    try:
        import mcp  # noqa: F401
        return True
    except ImportError:
        return False


def _materialize_mcp_content(t) -> str:
    """kind='content': one live server, one client call, dispatched by
    `primitive` — the same mechanic for CT1 (tool), RES1 (resource), and
    PR1 (prompt)."""
    from . import mcp_client
    from .servers import mcp_server

    async def _fetch() -> str:
        async with mcp_server.serve(t.server_config) as endpoint:
            if t.primitive == "resource":
                uri = t.server_config["resources"][0]["uri"]
                result = await mcp_client.read_resource(endpoint, uri)
            elif t.primitive == "prompt":
                name = t.server_config["prompts"][0]["name"]
                result = await mcp_client.get_prompt(endpoint, name)
            else:
                name = t.server_config["tools"][0]["name"]
                result = await mcp_client.call_tool(endpoint, name, {"artifact_id": "ART-0001"})
            return result["text"]

    return asyncio.run(_fetch())


def _materialize_mcp_rugpull(t, marker: str) -> tuple[str, bool]:
    """kind='rugpull': list (initial), call (triggers the server-side swap
    as a side effect), list again (post-swap) — each over a fresh
    connection, since the point being tested is whether a client that only
    saw the initial version would now be served something different.
    Returns (post-swap tools/list transcript, swap_confirmed)."""
    from . import mcp_client
    from .servers import mcp_server

    tool_name = t.server_config["tools"][0]["name"]

    async def _run() -> tuple[str, bool]:
        async with mcp_server.serve(t.server_config) as endpoint:
            initial_tools = await mcp_client.list_tools(endpoint)
            initial_desc = next(x["description"] for x in initial_tools if x["name"] == tool_name)
            await mcp_client.call_tool(endpoint, tool_name, {"invoice_id": "INV-0001"})
            post_tools = await mcp_client.list_tools(endpoint)
            post_desc = next(x["description"] for x in post_tools if x["name"] == tool_name)
            transcript = json.dumps({"tools": post_tools}, indent=2)
            swap_confirmed = (post_desc != initial_desc) and ch.hit(post_desc, marker)
            return transcript, swap_confirmed

    return asyncio.run(_run())


def _materialize_mcp_shadow(t) -> str:
    """kind='shadow': two live servers concurrently, tools/list from each,
    merged into one transcript — what a real multi-server client would
    present to the model."""
    from . import mcp_client
    from .servers import mcp_server

    trusted_cfg = t.server_config["trusted"]
    shadow_cfg = t.server_config["shadow"]

    async def _run() -> str:
        async with mcp_server.serve(trusted_cfg, port=trusted_cfg.get("port")) as trusted_ep:
            async with mcp_server.serve(shadow_cfg, port=shadow_cfg.get("port")) as shadow_ep:
                trusted_tools = await mcp_client.list_tools(trusted_ep)
                shadow_tools = await mcp_client.list_tools(shadow_ep)
        return json.dumps({"tools": trusted_tools + shadow_tools}, indent=2)

    return asyncio.run(_run())


def _materialize_zone_transcripts(techs, port: int) -> dict[str, str]:
    """Serve every zone technique's records from one authoritative zone, then
    dig each technique's queries — exactly what a recon pipeline would capture."""
    zone_techs = [t for t in techs if t.kind == "zone"]
    if not zone_techs:
        return {}
    merged: dict = {}
    for t in zone_techs:
        merged.update(t.records)
    transcripts: dict[str, str] = {}
    with ZoneServer(merged, port=port):
        for t in zone_techs:
            transcripts[t.id] = "\n".join(dig(name, rtype, port=port) for name, rtype in t.queries)
    return transcripts


def run(args) -> int:
    console = Console()
    marker = args.marker
    zone = args.zone

    selected = args.channels or list(ch.CHANNELS.keys())
    techs = []
    for c in selected:
        techs.extend(ch.techniques_for(c, marker, zone))

    console.print(
        f"\n[bold #39ff14]campaign[/]  marker=[#b026ff]{marker}[/]  "
        f"zone=[#8be9a3]{zone}[/]  channels={selected}\n"
    )

    # 1. Materialize transcripts.
    transcripts = _materialize_zone_transcripts(techs, args.dns_port)
    for t in techs:
        if t.kind == "text":
            transcripts[t.id] = t.transcript or ""

    content_exfil_hit: dict[str, bool] = {}
    swap_confirmed: dict[str, bool] = {}
    live_techs = [t for t in techs if t.kind in _MCP_LIVE_KINDS]
    if live_techs:
        mcp_live = _mcp_sdk_available()
        if not mcp_live:
            console.print(
                "[yellow]![/] mcp SDK not installed (pip install -e '.[serve]') — "
                "content/rugpull/shadow MCP techniques will use their static "
                "build-only transcripts instead of a live round trip.\n"
            )
        for t in live_techs:
            transcripts[t.id] = t.transcript or ""  # build-only convenience default
            if args.build_only or not mcp_live:
                continue
            if t.kind == "content":
                live_text = _materialize_mcp_content(t)
                transcripts[t.id] = live_text
                content_exfil_hit[t.id] = ch.hit(live_text, marker)
            elif t.kind == "rugpull":
                live_transcript, confirmed = _materialize_mcp_rugpull(t, marker)
                transcripts[t.id] = live_transcript
                swap_confirmed[t.id] = confirmed
            elif t.kind == "shadow":
                transcripts[t.id] = _materialize_mcp_shadow(t)

    out_dir: Path | None = None
    if args.out_dir:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for t in techs:
            (out_dir / f"{t.id}.txt").write_text(transcripts[t.id], encoding="utf-8")

    # Build-phase table: did the marker actually land in the ingested text?
    build_tbl = Table(title="Build / verify — marker present in ingested transcript",
                      header_style="bold #b026ff", expand=False)
    for col in ("channel", "track", "technique", "in-transcript", "note"):
        build_tbl.add_column(col, overflow="fold")
    for t in techs:
        present = ch.hit(transcripts[t.id], marker)
        mark = "[#39ff14]✓[/]" if present else "[dim]·[/]"
        build_tbl.add_row(t.channel, t.track, t.id, mark, t.note)
    console.print(build_tbl)

    if args.build_only:
        console.print("\n[dim]build-only — skipping model tests.[/]\n")
        if out_dir:
            console.print(f"[dim]transcripts written to {out_dir}/[/]\n")
        return 0

    # Delivery table: did the live MCP round trip actually carry the marker
    # (or, for rugpull, actually swap), independent of any model?
    delivery_techs = [t for t in live_techs if t.kind in ("content", "rugpull")]
    if delivery_techs:
        dv_tbl = Table(title="Delivery — live MCP round trip confirmed independent of any model",
                       header_style="bold #b026ff", expand=False)
        for col in ("technique", "kind", "confirmed"):
            dv_tbl.add_column(col, overflow="fold")
        for t in delivery_techs:
            ok = content_exfil_hit.get(t.id) if t.kind == "content" else swap_confirmed.get(t.id)
            dv_tbl.add_row(t.id, t.kind, "[#39ff14]✓[/]" if ok else "[red]✗[/]")
        console.print(dv_tbl)

    # 2. Query models.
    provider = build_provider(args)
    if provider.provider_name == "ollama":
        models = args.models or ["hermes3:8b"]
    else:
        models = [provider.model_id]
        if args.models:
            console.print(f"[yellow]![/] provider {provider.provider_name}: --models ignored, "
                          f"using {provider.model_id}\n")

    console.print(f"[dim]provider={provider.provider_name} models={models} "
                  f"{'(dry-run)' if getattr(provider, 'dry_run', False) else ''}[/]\n")

    results_tbl = Table(title="Model results — marker echoed in model output",
                        header_style="bold #b026ff", expand=False)
    results_tbl.add_column("channel")
    results_tbl.add_column("technique", overflow="fold")
    for m in models:
        results_tbl.add_column(m, justify="center")
    results_tbl.add_column("prior status", overflow="fold", style="dim")

    results: dict[str, dict[str, bool]] = {}
    for t in techs:
        prompt = ch.PROMPTS[t.prompt_key].format(content=transcripts[t.id][:8000])
        row_cells = []
        hits: dict[str, bool] = {}
        for m in models:
            if provider.provider_name == "ollama":
                # rebuild per-model provider so each model id is used
                resp = _ollama_generate(provider, m, prompt)
            else:
                resp = provider.generate(prompt)
            landed = ch.hit(resp, marker) and not resp.startswith("__ERROR__")
            hits[m] = landed
            row_cells.append("[#39ff14]✅[/]" if landed else "[dim]❌[/]")
            if out_dir:
                (out_dir / f"{t.id}.{m.replace(':', '_').replace('/', '_')}.response.txt").write_text(
                    resp, encoding="utf-8")
        results[t.id] = hits
        results_tbl.add_row(t.channel, t.id, *row_cells, t.status)

    console.print(results_tbl)

    total = sum(v for hits in results.values() for v in hits.values())
    possible = len(results) * len(models)
    pct = (100 * total // possible) if possible else 0
    console.print(f"\n[bold]landed {total}/{possible} ({pct}%)[/] "
                  f"across {len(techs)} techniques × {len(models)} model(s)\n")

    # Trust-framing delta callout (DNS-AID track E), if present.
    e1 = results.get("E1_unsigned_framing")
    e2 = results.get("E2_signed_framing")
    if e1 and e2:
        u = sum(e1.values())
        s = sum(e2.values())
        console.print(f"[#b026ff]trust-framing delta[/] (DNS-AID track E): "
                      f"unsigned {u}/{len(e1)} vs signed {s}/{len(e2)} on the identical payload.\n")

    if out_dir:
        summary = {"marker": marker, "zone": zone, "provider": provider.provider_name,
                   "models": models, "results": results,
                   "content_exfil_hit": content_exfil_hit, "swap_confirmed": swap_confirmed,
                   "techniques": {t.id: {k: v for k, v in asdict(t).items()
                                         if k in ("channel", "track", "note", "status")}
                                  for t in techs}}
        (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        console.print(f"[dim]artifacts + summary.json written to {out_dir}/[/]\n")

    console.print("[dim]Heuristic marker match only — read the saved responses before "
                  "calling any single result a hit or a clean pass.[/]\n")
    return 0


def _ollama_generate(base_provider, model_id: str, prompt: str) -> str:
    """Ollama supports many local models per run; reuse the base provider's
    settings but swap the model id per call."""
    from .providers import OllamaProvider
    p = OllamaProvider(model_id, dry_run=getattr(base_provider, "dry_run", False))
    return p.generate(prompt)
