"""
campaign.py — the POISONVINE orchestrator ("the vine").

Walks the channel registry, materializes each technique's transcript (serving a
single throwaway DNS zone and running real `dig` for the DNS/SVCB techniques,
rendering JSON/text directly for the rest), wraps each in its channel's prompt,
sends it to the target model(s), and reports which channels landed the marker.

Self-contained: needs only dnslib + stdlib + a provider. The live TLS/MCP path
(`serve-mcp` + `query --live-endpoint`) is separate and optional.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import channels as ch
from .providers import build_provider
from .servers.dns_server import DEFAULT_DNS_PORT, ZoneServer, dig


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
