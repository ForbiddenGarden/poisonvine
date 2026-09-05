"""
POISONVINE channel registry.

A *channel* is a DNS-borne surface through which attacker-controlled text can
reach an LLM's context. A *technique* is one concrete injection within a channel
(e.g. "payload in an SPF-mimicking TXT record"). Every technique here reproduces
a result already validated in the research this framework grew out of.

Each technique renders to a `transcript` — the exact text a real pipeline would
ingest — either directly ("text": MCP tool-list JSON, capability-doc JSON) or by
serving a throwaway DNS zone and running real `dig` ("zone"). The campaign
orchestrator (campaign.py) walks the registry, produces each transcript, wraps
it in the channel's prompt, sends it to a target model, and checks for the
marker.
"""

from __future__ import annotations

from .base import PROMPTS, Technique, hit
from . import agent_cards, classic_dns, dns_aid, mcp

CHANNELS = {
    "classic_dns": classic_dns,
    "dns_aid": dns_aid,
    "mcp": mcp,
    "agent_cards": agent_cards,
}

CHANNEL_TITLES = {
    "classic_dns": "Classic DNS / WHOIS records",
    "dns_aid": "DNS-AID / SVCB agent discovery",
    "mcp": "MCP tool-poisoning over discovered endpoints (14 techniques)",
    "agent_cards": "A2A agent cards / llms.txt / agents.txt (4 techniques)",
}


def all_techniques(marker: str, zone: str) -> list[Technique]:
    out: list[Technique] = []
    for mod in CHANNELS.values():
        out.extend(mod.techniques(marker, zone))
    return out


def techniques_for(channel: str, marker: str, zone: str) -> list[Technique]:
    mod = CHANNELS.get(channel)
    if mod is None:
        raise ValueError(f"unknown channel {channel!r}; choices: {sorted(CHANNELS)}")
    return mod.techniques(marker, zone)


__all__ = [
    "PROMPTS", "Technique", "hit",
    "CHANNELS", "CHANNEL_TITLES", "all_techniques", "techniques_for",
]
