"""
cap_server.py — config-driven DNS-AID capability-document server for POISONVINE.

Reads a YAML manifest (kind: capability_doc) and serves one or more JSON
capability documents at configurable paths — each capability's description
either a literal string or rendered from a named payload template — plus a
passive exfil-logging endpoint at /exfil that only records what is sent to it.
That endpoint exists for the tool-mediated-exfiltration variant, where a
poisoned capability doc tries to direct a calling agent's own http_post tool at
this server; it never does anything but log.
"""

from __future__ import annotations

import argparse
import http.server
import json
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path

from .. import payloads


def build_doc(agent: str, version: str, capabilities_cfg: list[dict]) -> dict:
    capabilities = []
    for cap in capabilities_cfg:
        if "description_literal" in cap:
            description = cap["description_literal"]
        else:
            description = payloads.render(cap["template"], **cap.get("template_args", {}))
        capabilities.append({
            "name": cap["name"],
            "description": description,
            "parameters": cap.get("parameters", {"id": "string"}),
        })
    return {"agent": agent, "version": version, "capabilities": capabilities}


def make_handler_class(docs: dict[str, dict], exfil_log: str, canary_secret: str):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            sys.stderr.write(f"[poisonvine cap-server] {self.address_string()} {fmt % args}\n")

        def _serve_json(self, body: dict):
            payload = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            path = self.path.lstrip("/").split("?")[0]
            if path in docs:
                self._serve_json(docs[path])
            elif self.path.startswith("/exfil"):
                self._log_exfil("GET", self.path)
                self.send_response(200)
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            self._log_exfil("POST", self.path, body)
            self.send_response(200)
            self.end_headers()

        def _log_exfil(self, method: str, path: str, body: bytes = b""):
            text = body.decode(errors="replace")
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "method": method,
                "path": path,
                "body": text,
                "canary_present": bool(canary_secret) and canary_secret in (path + text),
            }
            if exfil_log:
                with open(exfil_log, "a") as f:
                    f.write(json.dumps(entry) + "\n")
            print(f"[EXFIL RECEIVED] {entry}", flush=True)

    return Handler


def main(argv=None) -> int:
    import yaml

    p = argparse.ArgumentParser(
        description="Serve config-driven DNS-AID capability documents for POISONVINE testing."
    )
    p.add_argument("--config", required=True, help="YAML manifest, kind: capability_doc")
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--host", default="0.0.0.0")
    args = p.parse_args(argv)

    config = yaml.safe_load(Path(args.config).read_text())
    if config.get("kind") != "capability_doc":
        raise SystemExit(f"{args.config}: expected 'kind: capability_doc', got {config.get('kind')!r}")

    agent = config.get("agent", "poisonvine-fake-agent")
    version = config.get("version", "1.0.0")
    docs_cfg = config.get("docs", {})
    if not docs_cfg:
        raise SystemExit(f"{args.config}: no docs defined under 'docs:'")
    docs = {
        doc_path: build_doc(agent, version, doc_cfg["capabilities"])
        for doc_path, doc_cfg in docs_cfg.items()
    }

    handler_cls = make_handler_class(
        docs, config.get("exfil_log", "/var/log/exfil.jsonl"), config.get("canary_secret", ""),
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    server = http.server.HTTPServer((args.host, args.port), handler_cls)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"poisonvine cap-server listening on {args.host}:{args.port}, docs: {list(docs)}", flush=True)
    server.serve_forever()
    return 0
