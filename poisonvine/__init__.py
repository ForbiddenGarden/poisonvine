"""POISONVINE — a general-purpose prompt-injection testing framework.

Authorized security research use only. POISONVINE lets researchers test their
own AI pipelines, agent-discovery deployments, and MCP servers for
prompt-injection exposure across two surfaces: DNS-borne channels (classic
DNS/WHOIS records, DNS-AID / SVCB agent discovery) and the MCP protocol
surface directly (tool-description poisoning, tool-result/resource/prompt
content poisoning, rug-pulls, and cross-server tool shadowing).

Point it only at infrastructure you control. See README.md.
"""

__version__ = "0.2.0"
__all__ = ["__version__"]
