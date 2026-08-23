"""
POISONVINE — the monolith CLI that drives every channel and server.

    pv                      show the banner + quickstart
    pv channels             catalog every confirmed injection technique
    pv templates            list the payload-text templates
    pv providers            list inference providers, env keys, default models
    pv campaign             run the full injection matrix against a model
    pv serve-dns            serve a poisoned authoritative zone for manual testing
    pv serve-mcp            serve a poisoned MCP tool endpoint (needs `serve` extra)
    pv serve-cap            serve poisoned DNS-AID capability documents
    pv query                send captured tool/record text to a target model
    pv gen-cert             mint a self-signed test cert for the TLS servers

Authorized research use only. Point it at infrastructure you control.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__


def _emit_banner() -> None:
    if os.environ.get("POISONVINE_NO_BANNER") or "--no-banner" in sys.argv:
        return
    from .branding import banner
    # Banner to stderr so stdout stays clean for piping/redirection.
    sys.stderr.write(banner(__version__, no_color=not sys.stderr.isatty()))
    sys.stderr.write("\n")


# ── quickstart (bare invocation) ───────────────────────────────────────────

def _quickstart(console=None) -> int:
    from rich.console import Console
    from rich.panel import Panel

    console = console or Console()
    flows = [
        ("pv channels", "catalog every confirmed technique"),
        ("pv campaign --build-only", "materialize the full matrix, no model calls"),
        ("pv campaign --provider ollama --models hermes3:8b command-r", "run it against local models"),
        ("pv campaign --channel dns_aid --provider anthropic\n"
         "    --provider-model claude-haiku-4-5-20251001", "run one channel against Claude"),
        ("pv campaign --channel mcp --provider anthropic\n"
         "    --provider-model claude-haiku-4-5-20251001", "live MCP rug-pulls, shadowing & content-poisoning"),
        ("pv serve-dns --channel classic_dns", "serve a poisoned zone, then dig it yourself"),
        ("pv query --tools-file caught.json --provider anthropic --marker SIGMA",
         "test one captured tool-list against a model"),
    ]
    lines = [
        "[bold #39ff14]POISONVINE[/] tests your own AI pipelines, agent-discovery",
        "deployments, and MCP servers for prompt-injection exposure — DNS-borne",
        "channels and the MCP protocol surface directly.",
        "",
        "[bold]Common flows[/]",
    ]
    for cmd, desc in flows:
        cmd_lines = cmd.split("\n")
        lines.append(f"  [#b026ff]{cmd_lines[0]}[/]")
        for extra in cmd_lines[1:]:
            lines.append(f"  [#b026ff]{extra}[/]")
        lines.append(f"      [dim]{desc}[/]")
    lines += [
        "",
        "[dim]Every subcommand supports --help. API keys come from env vars only",
        "(ANTHROPIC_API_KEY, OPENAI_API_KEY, ...), never flags.[/]",
    ]
    console.print(Panel("\n".join(lines), title="[bold]quickstart[/]",
                        border_style="#2fbf4f", expand=False))
    return 0


# ── catalog commands ───────────────────────────────────────────────────────

def _cmd_channels(_args, rest) -> int:
    from rich.console import Console
    from rich.table import Table

    from . import channels as ch

    console = Console()
    for cid, mod in ch.CHANNELS.items():
        techs = mod.techniques("SIGMA", "poisonvine.test")
        tbl = Table(title=f"[bold #39ff14]{cid}[/] — {ch.CHANNEL_TITLES[cid]}",
                    header_style="bold #b026ff", expand=False)
        for col in ("track", "technique", "kind", "prior status"):
            tbl.add_column(col, overflow="fold")
        for t in techs:
            tbl.add_row(t.track, t.id, t.kind, t.status)
        console.print(tbl)
        console.print()
    console.print("[dim]Run  pv campaign --channel <id>  to exercise one channel, "
                  "or omit --channel for all three.[/]")
    return 0


def _cmd_templates(_args, rest) -> int:
    from rich.console import Console
    from rich.table import Table

    from . import payloads

    console = Console()
    tbl = Table(title="[bold #39ff14]payload templates[/]", header_style="bold #b026ff", expand=False)
    for col in ("template", "family", "requires", "description"):
        tbl.add_column(col, overflow="fold")
    for name, tmpl in sorted(payloads.TEMPLATES.items()):
        tbl.add_row(name, tmpl.family, ", ".join(tmpl.required_args) or "—", tmpl.description)
    console.print(tbl)
    return 0


def _cmd_providers(_args, rest) -> int:
    from rich.console import Console
    from rich.table import Table

    from .providers import provider_catalog

    console = Console()
    tbl = Table(title="[bold #39ff14]inference providers[/]", header_style="bold #b026ff", expand=False)
    for col in ("provider", "kind", "default model", "env var(s)", "endpoint"):
        tbl.add_column(col, overflow="fold")
    for row in provider_catalog():
        tbl.add_row(row["provider"], row["kind"], row["default_model"], row["env"], row["endpoint"])
    console.print(tbl)
    console.print("[dim]Keys come from env vars only, never flags. Default models are "
                  "placeholders — pin an exact id with --provider-model.[/]")
    return 0


# ── campaign ───────────────────────────────────────────────────────────────

def _cmd_campaign(args, rest) -> int:
    from . import campaign
    return campaign.run(args)


# ── serve-dns ──────────────────────────────────────────────────────────────

def _cmd_serve_dns(args, rest) -> int:
    from rich.console import Console

    from . import channels as ch
    from .servers.dns_server import ZoneServer

    console = Console()
    selected = args.channels or ["classic_dns", "dns_aid"]
    techs = []
    for c in selected:
        techs.extend(ch.techniques_for(c, args.marker, args.zone))
    zone_techs = [t for t in techs if t.kind == "zone"]
    if not zone_techs:
        console.print("[yellow]selected channels have no DNS-servable techniques "
                      "(mcp/cap are text/TLS channels — use serve-mcp / serve-cap).[/]")
        return 1

    merged: dict = {}
    for t in zone_techs:
        merged.update(t.records)

    console.print(f"[bold #39ff14]serve-dns[/]  zone=[#8be9a3]{args.zone}[/]  "
                  f"marker=[#b026ff]{args.marker}[/]  "
                  f"listening on 127.0.0.1:{args.dns_port}  ({len(merged)} record sets)\n")
    console.print("[dim]Point your own pipeline / agent DNS tool at this resolver, or try:[/]")
    for t in zone_techs[:8]:
        name, rtype = t.queries[0]
        console.print(f"  [#b026ff]dig @127.0.0.1 -p {args.dns_port} {name} {rtype}[/]   "
                      f"[dim]# {t.id}[/]")
    console.print("\n[dim]Ctrl-C to stop.[/]\n")

    server = ZoneServer(merged, port=args.dns_port).start()
    try:
        import time
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        console.print("\n[dim]stopped.[/]")
    finally:
        server.stop()
    return 0


# ── passthrough commands (own argparse) ────────────────────────────────────

def _cmd_serve_mcp(_args, rest) -> int:
    from .servers import mcp_server
    return mcp_server.main(rest)


def _cmd_serve_cap(_args, rest) -> int:
    from .servers import cap_server
    return cap_server.main(rest)


def _cmd_query(_args, rest) -> int:
    from . import query
    return query.main(rest)


def _cmd_gen_cert(_args, rest) -> int:
    from . import certs
    return certs.main(rest)


# ── parser ─────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    from .providers import add_provider_args

    p = argparse.ArgumentParser(
        prog="pv", description="POISONVINE — prompt-injection testing framework "
                               "for DNS-borne channels and the MCP protocol surface.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Authorized research use only. Point it at infrastructure you control.")
    p.add_argument("--version", action="version", version=f"poisonvine {__version__}")
    p.add_argument("--no-banner", action="store_true", help="Suppress the launch banner.")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("channels", help="Catalog every confirmed injection technique.")
    sub.add_parser("templates", help="List payload-text templates.")
    sub.add_parser("providers", help="List inference providers, env keys, and default models.")

    camp = sub.add_parser("campaign", help="Run the full DNS injection matrix against a model.")
    camp.add_argument("--channel", dest="channels", action="append",
                      choices=["classic_dns", "dns_aid", "mcp"],
                      help="Restrict to a channel (repeatable). Default: all three.")
    camp.add_argument("--marker", default="SIGMA")
    camp.add_argument("--zone", default="poisonvine.test")
    camp.add_argument("--dns-port", type=int, default=5353)
    camp.add_argument("--models", nargs="+", help="Ollama models to test (ignored for API providers).")
    camp.add_argument("--build-only", action="store_true", help="Build+verify transcripts, no model calls.")
    camp.add_argument("--out-dir", help="Write transcripts, responses, and summary.json here.")
    add_provider_args(camp)

    srv = sub.add_parser("serve-dns", help="Serve a poisoned authoritative zone for manual testing.")
    srv.add_argument("--channel", dest="channels", action="append",
                     choices=["classic_dns", "dns_aid"],
                     help="Channels to serve (repeatable). Default: classic_dns + dns_aid.")
    srv.add_argument("--marker", default="SIGMA")
    srv.add_argument("--zone", default="poisonvine.test")
    srv.add_argument("--dns-port", type=int, default=5353)

    # Passthrough commands parse their own args; add_help=False keeps -h routed to them.
    sub.add_parser("serve-mcp", add_help=False,
                   help="Serve a poisoned MCP tool endpoint (needs `serve` extra).")
    sub.add_parser("serve-cap", add_help=False,
                   help="Serve poisoned DNS-AID capability documents (needs `serve` extra).")
    sub.add_parser("query", add_help=False,
                   help="Send captured tool/record text to a target model.")
    sub.add_parser("gen-cert", add_help=False, help="Mint a self-signed test cert.")
    return p


_HANDLERS = {
    "channels": _cmd_channels,
    "templates": _cmd_templates,
    "providers": _cmd_providers,
    "campaign": _cmd_campaign,
    "serve-dns": _cmd_serve_dns,
    "serve-mcp": _cmd_serve_mcp,
    "serve-cap": _cmd_serve_cap,
    "query": _cmd_query,
    "gen-cert": _cmd_gen_cert,
}

# Commands that manage their own argparse — everything after the command name
# is handed to them untouched.
_PASSTHROUGH = {"serve-mcp", "serve-cap", "query", "gen-cert"}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    _emit_banner()

    # For passthrough commands, split argv at the command and forward the rest
    # so their own parsers (not pv's) handle -h and flags.
    for i, tok in enumerate(argv):
        if tok in _PASSTHROUGH:
            return _HANDLERS[tok](None, argv[i + 1:])

    parser = _build_parser()
    args, rest = parser.parse_known_args(argv)
    if not args.command:
        return _quickstart()
    handler = _HANDLERS.get(args.command)
    if handler is None:
        parser.print_help()
        return 1
    return handler(args, rest)


if __name__ == "__main__":
    raise SystemExit(main())
