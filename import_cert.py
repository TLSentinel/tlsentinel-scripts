#!/usr/bin/env python3
"""
import_cert.py

Ingest a certificate file into TLSentinel and optionally link it to an
endpoint. Supports PEM, DER, and PKCS#12 (.p12/.pfx) files.

PKCS#12 support requires the 'cryptography' package:
    pip install cryptography

Usage:
    python import_cert.py <cert_file> [options]

Examples:
    # Ingest a PEM file
    python import_cert.py partner.pem --server https://tlsentinel.example.com --token <token>

    # Ingest a DER file
    python import_cert.py partner.cer --server https://tlsentinel.example.com --token <token>

    # Ingest a P12 and link to an existing endpoint by name
    python import_cert.py partner.p12 --p12-password secret \\
        --server https://tlsentinel.example.com --token <token> \\
        --endpoint-name "Acme Supplier"

    # Ingest and create a new manual endpoint
    python import_cert.py partner.pem \\
        --server https://tlsentinel.example.com --token <token> \\
        --create-endpoint --endpoint-name "Acme Supplier"
"""

import argparse
import base64
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


# ---------------------------------------------------------------------------
# Certificate loading
# ---------------------------------------------------------------------------

def load_pem(path: Path) -> str:
    """Read a PEM file and return its contents."""
    return path.read_text(errors="replace").strip()


def load_der(path: Path) -> str:
    """Read a DER file and return base64-encoded contents."""
    return base64.b64encode(path.read_bytes()).decode()


def load_p12(path: Path, password: str | None) -> list[str]:
    """
    Extract all certificates from a PKCS#12 file.
    Returns a list of PEM strings (leaf cert + any chain certs).
    Requires the 'cryptography' package.
    """
    try:
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12
    except ImportError:
        print("  PKCS#12 support requires the 'cryptography' package.", file=sys.stderr)
        print("  Install it with: pip install cryptography", file=sys.stderr)
        sys.exit(1)

    pw = password.encode() if password else None
    p12 = load_pkcs12(path.read_bytes(), pw)

    pems: list[str] = []

    # Leaf / end-entity cert
    if p12.cert:
        pems.append(p12.cert.certificate.public_bytes(Encoding.PEM).decode())

    # Additional chain certs
    for ca in (p12.additional_certs or []):
        pems.append(ca.certificate.public_bytes(Encoding.PEM).decode())

    return pems


def detect_and_load(path: Path, p12_password: str | None) -> list[dict]:
    """
    Auto-detect file type and return a list of API request bodies:
      {"certificatePem": "..."}  or  {"certificateDerBase64": "..."}
    """
    suffix = path.suffix.lower()

    if suffix in (".p12", ".pfx"):
        pems = load_p12(path, p12_password)
        return [{"certificatePem": pem} for pem in pems]

    raw = path.read_bytes()

    # PEM: starts with -----
    if raw.lstrip()[:5] == b"-----":
        return [{"certificatePem": raw.decode(errors="replace").strip()}]

    # Assume DER for everything else
    return [{"certificateDerBase64": base64.b64encode(raw).decode()}]


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def api_request(server: str, token: str, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    """Make an authenticated API request. Returns (status_code, response_body)."""
    url = f"{server.rstrip('/')}/api/v1{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method=method,
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read()
        return resp.status, (json.loads(raw) if raw else {})


def ingest_cert_body(server: str, token: str, body: dict) -> tuple[bool, str, str]:
    """
    POST /certificates. Returns (success, fingerprint, message).
    """
    try:
        status, resp = api_request(server, token, "POST", "/certificates", body)
        fp = resp.get("fingerprint", "")
        if status == 201:
            return True, fp, f"ingested  {fp[:16]}…"
        else:
            return True, fp, f"already present  {fp[:16]}…"
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="replace")
        return False, "", f"HTTP {e.code}: {msg}"
    except Exception as e:
        return False, "", str(e)


def link_cert_to_endpoint(server: str, token: str, endpoint_id: str, pem: str) -> tuple[bool, str]:
    """POST /endpoints/{id}/certificate."""
    try:
        api_request(server, token, "POST", f"/endpoints/{endpoint_id}/certificate", {"pem": pem})
        return True, "linked"
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="replace")
        return False, f"HTTP {e.code}: {msg}"
    except Exception as e:
        return False, str(e)


def find_endpoint_by_name(server: str, token: str, name: str) -> str | None:
    """Search endpoints by name, return the ID of the first exact match."""
    try:
        _, resp = api_request(server, token, "GET",
                              f"/endpoints?search={urllib.parse.quote(name)}&page_size=10")
        for item in resp.get("items", []):
            if item.get("name", "").lower() == name.lower():
                return item["id"]
    except Exception:
        pass
    return None


def create_manual_endpoint(server: str, token: str, name: str) -> str:
    """POST /endpoints to create a new manual endpoint. Returns the new ID."""
    _, resp = api_request(server, token, "POST", "/endpoints", {"name": name, "type": "manual"})
    return resp["id"]


def pem_from_body(body: dict) -> str | None:
    """Extract a PEM string from an API request body for linking."""
    if "certificatePem" in body:
        return body["certificatePem"]
    if "certificateDerBase64" in body:
        import textwrap
        b64 = body["certificateDerBase64"]
        wrapped = textwrap.fill(b64, width=64)
        return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ingest a certificate file into TLSentinel.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file", help="Certificate file (.pem, .crt, .cer, .der, .p12, .pfx)")
    parser.add_argument("--server", default="http://localhost:8080",
                        help="TLSentinel server base URL (default: http://localhost:8080)")
    parser.add_argument("--token", default="", help="Bearer token for API authentication")
    parser.add_argument("--p12-password", metavar="PASS", default=None,
                        help="Password for PKCS#12 files (omit if unprotected)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Detect file type and show what would be imported without calling the API")

    ep_group = parser.add_argument_group("endpoint linking (optional)")
    ep_group.add_argument("--endpoint-id",   metavar="UUID",
                          help="Link cert to an existing endpoint by ID")
    ep_group.add_argument("--endpoint-name", metavar="NAME",
                          help="Link cert to an existing endpoint by name, or use with --create-endpoint")
    ep_group.add_argument("--create-endpoint", action="store_true",
                          help="Create a new manual endpoint (requires --endpoint-name)")

    args = parser.parse_args()

    if args.create_endpoint and not args.endpoint_name:
        parser.error("--create-endpoint requires --endpoint-name")
    if args.endpoint_id and args.endpoint_name:
        parser.error("--endpoint-id and --endpoint-name are mutually exclusive")

    path = Path(args.file)
    if not path.exists():
        print(f"  File not found: {path}", file=sys.stderr)
        return 1

    print(f"\nLoading {path} …")
    try:
        bodies = detect_and_load(path, args.p12_password)
    except Exception as e:
        print(f"  Failed to load file: {e}", file=sys.stderr)
        return 1

    print(f"  Detected {len(bodies)} certificate(s)\n")

    if args.dry_run:
        for i, body in enumerate(bodies, 1):
            fmt = "PEM" if "certificatePem" in body else "DER (base64)"
            print(f"  [{i}] {fmt}")
        print()
        return 0

    if not args.token:
        print("  --token is required unless using --dry-run.", file=sys.stderr)
        return 1

    # Resolve endpoint ID
    endpoint_id: str | None = args.endpoint_id

    if args.create_endpoint:
        print(f"  Creating manual endpoint '{args.endpoint_name}' …")
        try:
            endpoint_id = create_manual_endpoint(args.server, args.token, args.endpoint_name)
            print(f"    ✓ created  {endpoint_id}\n")
        except urllib.error.HTTPError as e:
            print(f"    ✗ HTTP {e.code}: {e.read().decode(errors='replace')}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"    ✗ {e}", file=sys.stderr)
            return 1

    elif args.endpoint_name and not endpoint_id:
        print(f"  Looking up endpoint '{args.endpoint_name}' …")
        endpoint_id = find_endpoint_by_name(args.server, args.token, args.endpoint_name)
        if endpoint_id:
            print(f"    ✓ found  {endpoint_id}\n")
        else:
            print(f"    ✗ No endpoint found with name '{args.endpoint_name}'.", file=sys.stderr)
            return 1

    # Ingest
    ok_count = 0
    fail_count = 0

    for i, body in enumerate(bodies, 1):
        label = f"cert {i} of {len(bodies)}"
        print(f"  {label}")
        success, fp, msg = ingest_cert_body(args.server, args.token, body)
        print(f"    {'✓' if success else '✗'} ingest  {msg}")

        if success and endpoint_id:
            pem = pem_from_body(body)
            if pem:
                linked, link_msg = link_cert_to_endpoint(args.server, args.token, endpoint_id, pem)
                print(f"    {'✓' if linked else '✗'} link    {link_msg}")
                if not linked:
                    fail_count += 1

        if success:
            ok_count += 1
        else:
            fail_count += 1

    print(f"\nDone: {ok_count} ingested, {fail_count} failed.\n")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
