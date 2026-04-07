#!/usr/bin/env python3
"""
import_metadata_folder.py

Requires: tlsentinel-server >= v2026.4.4

Walk a folder of SAML metadata XML files, and for each file:
  - Use the filename (without extension) as the endpoint name
  - Check if a SAML endpoint with that name already exists
  - Create one if it does not
  - Ingest and link all certificates found in the metadata

Useful for bulk-onboarding a directory of trading partner or IdP metadata files.

Usage:
    python import_metadata_folder.py <folder> --server <url> --token <token>

Examples:
    TOKEN=$(python login.py --server https://tlsentinel.example.com --username admin)

    python import_metadata_folder.py ./metadata/ \\
        --server https://tlsentinel.example.com --token "$TOKEN"

    # Dry run — show what would be created without touching the API
    python import_metadata_folder.py ./metadata/ --dry-run
"""

import argparse
import base64
import json
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path


# ---------------------------------------------------------------------------
# XML namespaces
# ---------------------------------------------------------------------------

NS = {
    "md":  "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds":  "http://www.w3.org/2000/09/xmldsig#",
}


# ---------------------------------------------------------------------------
# Cert extraction (same logic as import_metadata_certs.py)
# ---------------------------------------------------------------------------

class ExtractedCert:
    def __init__(self, use: str, index: int, der_b64: str):
        self.use = use
        self.index = index
        self.der_b64 = der_b64

    @property
    def pem(self) -> str:
        wrapped = textwrap.fill(self.der_b64.strip(), width=64)
        return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"


def extract_certs(root: ET.Element) -> list[ExtractedCert]:
    certs: list[ExtractedCert] = []
    entities = root.findall(".//md:EntityDescriptor", NS)
    if not entities and root.tag == f"{{{NS['md']}}}EntityDescriptor":
        entities = [root]

    for entity in entities:
        use_counters: dict[str, int] = {}
        for kd in entity.findall(".//md:KeyDescriptor", NS):
            use = kd.get("use", "unspecified")
            idx = use_counters.get(use, 0)
            use_counters[use] = idx + 1
            x509 = kd.find(".//ds:X509Certificate", NS)
            if x509 is not None and x509.text:
                der_b64 = x509.text.strip().replace("\n", "").replace("\r", "").replace(" ", "")
                certs.append(ExtractedCert(use=use, index=idx, der_b64=der_b64))

    return certs


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def api_request(server: str, token: str, method: str, path: str, body: dict | None = None) -> dict:
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
        return json.loads(raw) if raw else {}


def find_endpoint_by_name(server: str, token: str, name: str) -> str | None:
    try:
        resp = api_request(server, token, "GET",
                           f"/endpoints?search={urllib.parse.quote(name)}&page_size=10")
        for item in resp.get("items", []):
            if item.get("name", "").lower() == name.lower():
                return item["id"]
    except Exception:
        pass
    return None


def create_saml_endpoint(server: str, token: str, name: str) -> str:
    resp = api_request(server, token, "POST", "/endpoints", {"name": name, "type": "saml"})
    return resp["id"]


def ingest_cert(server: str, token: str, cert: ExtractedCert) -> tuple[bool, str]:
    try:
        api_request(server, token, "POST", "/certificates", {"certificatePem": cert.pem})
        return True, "ok"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read().decode(errors='replace')}"
    except Exception as e:
        return False, str(e)


def link_cert(server: str, token: str, endpoint_id: str, cert: ExtractedCert) -> tuple[bool, str]:
    try:
        api_request(server, token, "POST", f"/endpoints/{endpoint_id}/certificate", {
            "pem": cert.pem,
            "certUse": cert.use,
        })
        return True, "linked"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read().decode(errors='replace')}"
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Process a single file
# ---------------------------------------------------------------------------

def process_file(path: Path, server: str, token: str, dry_run: bool) -> tuple[int, int]:
    """Process one XML file. Returns (ok_count, fail_count)."""
    name = path.stem  # filename without extension

    print(f"\n  {path.name}  →  '{name}'")

    # Parse XML
    try:
        root = ET.parse(path).getroot()
    except Exception as e:
        print(f"    ✗ failed to parse XML: {e}")
        return 0, 1

    certs = extract_certs(root)
    if not certs:
        print(f"    ✗ no certificates found")
        return 0, 1

    if dry_run:
        for cert in certs:
            try:
                size = len(base64.b64decode(cert.der_b64))
            except Exception:
                size = 0
            print(f"    [{cert.use:12s}]  {size} bytes DER")
        return len(certs), 0

    # Check / create endpoint
    endpoint_id = find_endpoint_by_name(server, token, name)
    if endpoint_id:
        print(f"    endpoint exists  {endpoint_id}")
    else:
        try:
            endpoint_id = create_saml_endpoint(server, token, name)
            print(f"    ✓ endpoint created  {endpoint_id}")
        except urllib.error.HTTPError as e:
            msg = e.read().decode(errors="replace")
            print(f"    ✗ failed to create endpoint: HTTP {e.code}: {msg}")
            return 0, 1
        except Exception as e:
            print(f"    ✗ failed to create endpoint: {e}")
            return 0, 1

    # Ingest and link certs
    ok = fail = 0
    for cert in certs:
        success, msg = ingest_cert(server, token, cert)
        if not success:
            print(f"    ✗ ingest [{cert.use}]: {msg}")
            fail += 1
            continue

        linked, link_msg = link_cert(server, token, endpoint_id, cert)
        if linked:
            print(f"    ✓ [{cert.use}]  {link_msg}")
            ok += 1
        else:
            print(f"    ✗ [{cert.use}]  link failed: {link_msg}")
            fail += 1

    return ok, fail


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bulk import SAML metadata XML files from a folder into TLSentinel.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("folder", help="Folder containing metadata XML files")
    parser.add_argument("--server", default="http://localhost:8080",
                        help="TLSentinel server base URL (default: http://localhost:8080)")
    parser.add_argument("--token", default="", help="Bearer token for API authentication")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse files and show what would be imported without calling the API")
    args = parser.parse_args()

    folder = Path(args.folder)
    if not folder.is_dir():
        print(f"Not a directory: {folder}", file=sys.stderr)
        return 1

    xml_files = sorted(folder.glob("*.xml"))
    if not xml_files:
        print(f"No XML files found in {folder}")
        return 0

    print(f"\nFound {len(xml_files)} XML file(s) in {folder}")

    if not args.dry_run and not args.token:
        print("--token is required unless using --dry-run.", file=sys.stderr)
        return 1

    total_ok = total_fail = 0

    for path in xml_files:
        ok, fail = process_file(path, args.server, args.token, args.dry_run)
        total_ok += ok
        total_fail += fail

    print(f"\nDone: {total_ok} certs imported, {total_fail} failed across {len(xml_files)} file(s).\n")
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
