"""
dns_server.py — reusable authoritative-zone engine for POISONVINE.

A pure-Python (dnslib) authoritative DNS server that serves an arbitrary
record set on a local unprivileged port, plus the low-level primitives channels
use to build poisoned records: TXT/A/CNAME/SOA and SVCB (DNS-AID) records, and
a `dig`-based extractor that produces exactly the text a recon pipeline would
feed an LLM.

SVCB (qtype 64) and HTTPS (qtype 65) share the RFC 9460 wire format; dnslib
only ships an RD class named `HTTPS`, reused here under qtype 64 by registering
SVCB into dnslib's QTYPE bimap at import. DNS-AID's custom SvcParamKeys have no
IANA codepoint yet, so they are pinned into the RFC 9460 private-use range
(65280–65534) rather than colliding with a future assignment.

No real DNS infrastructure is touched: everything binds 127.0.0.1 on an
unprivileged port and serves a throwaway zone (default: the RFC 2606 .test TLD).
"""

from __future__ import annotations

import subprocess
import time

from dnslib import QTYPE, RR
from dnslib.dns import HTTPS as _SVCB_RD
from dnslib.server import BaseResolver, DNSServer

DEFAULT_ZONE = "poisonvine.test"
DEFAULT_DNS_PORT = 5353  # unprivileged; real port 53 needs root

# Register SVCB (qtype 64) — dnslib has no built-in name, but its HTTPS RD
# class already implements the shared RFC 9460 wire format byte-for-byte.
QTYPE.forward[64] = "SVCB"
QTYPE.reverse["SVCB"] = 64

# Standard SvcParamKeys (RFC 9460 §14.3.2)
KEY_ALPN = 1
KEY_PORT = 3
# DNS-AID params — no IANA assignment yet; pinned into the private-use range.
KEY_CAP = 65280
KEY_CAP_SHA256 = 65281
KEY_BAP = 65282
KEY_POLICY = 65283
KEY_REALM = 65284


def fqdn(label: str, zone: str = DEFAULT_ZONE) -> str:
    return f"{label}.{zone}." if label else f"{zone}."


def alpn(*protocols: str) -> bytes:
    """RFC 9460 `alpn` SvcParamValue: length-prefixed protocol IDs. Each entry
    needs its 1-byte length prefix or a strict parser (real `dig`) rejects the
    whole record as FORMERR."""
    out = b""
    for p in protocols:
        pb = p.encode()
        out += bytes([len(pb)]) + pb
    return out


def svcb_rd(priority: int, target: str, params: dict) -> _SVCB_RD:
    """Build an SVCB RDATA object. `params` maps SvcParamKey int -> value
    (bytes used verbatim, anything else str()'d and encoded)."""
    target_labels = [] if target in (None, "", ".") else [
        seg.encode() for seg in target.rstrip(".").split(".")
    ]
    param_pairs = [
        (k, v if isinstance(v, (bytes, bytearray)) else str(v).encode())
        for k, v in params.items()
    ]
    return _SVCB_RD(priority, target_labels, param_pairs)


class ZoneResolver(BaseResolver):
    """Serves a static record map: {(qname, qtype_str): [rdata, ...]}."""

    def __init__(self, records: dict):
        self.records = records

    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".").lower() + "."
        qtype = QTYPE[request.q.qtype]
        for (name, rtype), values in self.records.items():
            if name.lower() == qname and rtype == qtype:
                for v in values:
                    reply.add_answer(RR(request.q.qname, getattr(QTYPE, rtype), rdata=v, ttl=60))
        return reply


class ZoneServer:
    """Thin lifecycle wrapper around a dnslib DNSServer bound to localhost."""

    def __init__(self, records: dict, port: int = DEFAULT_DNS_PORT, address: str = "127.0.0.1"):
        self.records = records
        self.port = port
        self.address = address
        self._server: DNSServer | None = None

    def start(self) -> "ZoneServer":
        self._server = DNSServer(ZoneResolver(self.records), port=self.port, address=self.address)
        self._server.start_thread()
        time.sleep(0.3)
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.stop()
            self._server = None

    def __enter__(self) -> "ZoneServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def dig(name: str, rtype: str, port: int = DEFAULT_DNS_PORT, server: str = "127.0.0.1") -> str:
    """Query the local zone with real `dig` — output matches what a recon tool
    (amass/subfinder/dnsx piped into an LLM) would actually hand a pipeline."""
    r = subprocess.run(
        ["dig", f"@{server}", "-p", str(port), name, rtype],
        capture_output=True, text=True, timeout=10,
    )
    return r.stdout
