"""
certs.py — self-signed test-certificate generation for POISONVINE servers.

Uses an openssl subprocess (ECDSA P-256). Test-only: these are meant to be
trusted explicitly by a testing client's cert store, never by a real CA chain.
"""

from __future__ import annotations

import argparse
import subprocess


def generate(cn: str, out_dir: str = ".", days: int = 30) -> tuple[str, str]:
    crt = f"{out_dir}/{cn}.crt"
    key = f"{out_dir}/{cn}.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", key, "-out", crt, "-days", str(days),
            "-subj", f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn}",
        ],
        check=True,
    )
    return crt, key


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Generate a self-signed ECDSA P-256 test certificate for a POISONVINE server."
    )
    p.add_argument("cn", help="Common name / SAN DNS name, e.g. evil-cap.orga.test")
    p.add_argument("-o", "--out-dir", default=".")
    p.add_argument("--days", type=int, default=30)
    args = p.parse_args(argv)

    crt, key = generate(args.cn, args.out_dir, args.days)
    print(f"wrote {crt} and {key}")
    print(
        "Append the .crt to the testing client's certifi cacert.pem to trust it "
        "(httpx/certifi don't use the OS trust store by default). If fetching "
        "through dns-aid-core's SSRF-hardened path, set "
        f"DNS_AID_FETCH_ALLOWLIST={args.cn} — its own documented test/dev override."
    )
    return 0
