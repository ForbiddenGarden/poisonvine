"""POISONVINE — a general-purpose DNS prompt-injection testing framework.

Authorized security research use only. POISONVINE lets researchers test their
own AI pipelines and agent-discovery deployments for prompt-injection exposure
across DNS-borne channels: classic DNS/WHOIS records, DNS-AID / SVCB agent
discovery, and MCP tool-poisoning served over discovered endpoints.

Point it only at infrastructure you control. See README.md.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
