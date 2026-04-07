#!/usr/bin/env python3
"""
import_metadata_certs.py

Parse an XML metadata file or URL containing embedded X.509 certificates
(e.g. SAML federation metadata), extract all certs, ingest them into
TLSentinel, and optionally create or link them to an endpoint.

Supports any XML format that uses <ds:X509Certificate> elements, including
SAML EntityDescriptor and EntitiesDescriptor (federation aggregate) documents.
No third-party dependencies required — stdlib only.

Usage:
    python import_metadata_certs.py <metadata.xml or URL> [options]

Examples:
    # Dry run — see what certs are in the file without touching the API
    python import_metadata_certs.py metadata.xml --dry-run

    # Ingest certs only
    python import_metadata_certs.py metadata.xml \\
        --server https://tlsentinel.example.com --token <token>

    # Ingest and create a new SAML endpoint linked to the certs
    python import_metadata_certs.py metadata.xml \\
        --server https://tlsentinel.example.com --token <token> \\
        --create-endpoint --endpoint-name "Okta IdP"

    # Ingest and link to an existing endpoint by ID
    python import_metadata_certs.py metadata.xml \\
        --server https://tlsentinel.example.com --token <token> \\
        --endpoint-id <uuid>

    # Ingest and link to an existing endpoint by name
    python import_metadata_certs.py metadata.xml \\
        --server https://tlsentinel.example.com --token <token> \\
        --endpoint-name "Okta IdP"
"""

import argparse
import base64
import json
import sys
import textwrap
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# XML namespaces used in SAML metadata
# ---------------------------------------------------------------------------

NS = {
    "md":   "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds":   "http://www.w3.org/2000/09/xmldsig#",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
}


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class ExtractedCert:
    entity_id: str
    use: str          # 'signing', 'encryption', or 'unspecified'
    index: int        # position within that use group, 0-based
    der_b64: str      # raw base64 from the XML (no headers)

    @property
    def pem(self) -> str:
        wrapped = textwrap.fill(self.der_b64.strip(), width=64)
        return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"

    @property
    def label(self) -> str:
        suffix = f" #{self.index + 1}" if self.index > 0 else ""
        return f"{self.entity_id} [{self.use}{suffix}]"


@dataclass
class IngestResult:
    cert: ExtractedCert
    success: bool
    fingerprint: str = ""
    message: str = ""


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def load_xml(source: str) -> ET.Element:
    """Load XML from a file path or URL."""
    if source.startswith("http://") or source.startswith("https://"):
        print(f"  Fetching {source} …")
        with urllib.request.urlopen(source, timeout=30) as resp:
            data = resp.read()
        return ET.fromstring(data)
    else:
        return ET.parse(source).getroot()


def extract_certs(root: ET.Element) -> list[ExtractedCert]:
    """
    Walk the metadata tree and collect all X509Certificate values.
    Handles both EntityDescriptor (single IdP) and EntitiesDescriptor
    (federation aggregate) documents.
    """
    certs: list[ExtractedCert] = []

    entities = root.findall(".//md:EntityDescriptor", NS)
    if not entities:
        if root.tag == f"{{{NS['md']}}}EntityDescriptor":
            entities = [root]

    for entity in entities:
        entity_id = entity.get("entityID", "<unknown>")
        use_counters: dict[str, int] = {}

        for kd in entity.findall(".//md:KeyDescriptor", NS):
            use = kd.get("use", "unspecified")
            idx = use_counters.get(use, 0)
            use_counters[use] = idx + 1

            x509 = kd.find(".//ds:X509Certificate", NS)
            if x509 is not None and x509.text:
                der_b64 = x509.text.strip().replace("\n", "").replace("\r", "").replace(" ", "")
                certs.append(ExtractedCert(
                    entity_id=entity_id,
                    use=use,
                    index=idx,
                    der_b64=der_b64,
                ))

    return certs


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def api_request(server: str, token: str, method: str, path: str, body: dict | None = None) -> dict:
    """Make an authenticated API request. Raises on HTTP error."""
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


def ingest_cert(server: str, token: str, cert: ExtractedCert) -> IngestResult:
    """POST /certificates — ingest a single cert. Returns IngestResult."""
    try:
        resp = api_request(server, token, "POST", "/certificates", {"certificatePem": cert.pem})
        fp = resp.get("fingerprint", "")
        # Determine new vs existing from response (201 = new, 200 = existing).
        # urllib doesn't surface status easily after urlopen, so we check via a
        # second GET — simpler: just report the fingerprint either way.
        msg = f"fingerprint {fp[:16]}…" if fp else "ok"
        return IngestResult(cert=cert, success=True, fingerprint=fp, message=msg)
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="replace")
        return IngestResult(cert=cert, success=False, message=f"HTTP {e.code}: {msg}")
    except Exception as e:
        return IngestResult(cert=cert, success=False, message=str(e))


def link_cert_to_endpoint(server: str, token: str, endpoint_id: str, result: IngestResult) -> tuple[bool, str]:
    """POST /endpoints/{id}/certificate to link an ingested cert."""
    try:
        api_request(server, token, "POST", f"/endpoints/{endpoint_id}/certificate", {
            "pem": result.cert.pem,
            "certUse": result.cert.use,  # signing / encryption / unspecified
        })
        return True, "linked"
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="replace")
        return False, f"HTTP {e.code}: {msg}"
    except Exception as e:
        return False, str(e)


def find_endpoint_by_name(server: str, token: str, name: str) -> str | None:
    """Search endpoints by name, return the ID of the first exact match."""
    try:
        resp = api_request(server, token, "GET", f"/endpoints?search={urllib.parse.quote(name)}&page_size=10")
        for item in resp.get("items", []):
            if item.get("name", "").lower() == name.lower():
                return item["id"]
    except Exception:
        pass
    return None


def create_saml_endpoint(server: str, token: str, name: str, metadata_url: str | None) -> str:
    """POST /endpoints to create a new SAML endpoint. Returns the new endpoint ID."""
    body: dict = {"name": name, "type": "saml"}
    if metadata_url and metadata_url.startswith("http"):
        body["url"] = metadata_url
    resp = api_request(server, token, "POST", "/endpoints", body)
    return resp["id"]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    import urllib.parse  # noqa: PLC0415 — only needed here

    parser = argparse.ArgumentParser(
        description="Extract and ingest certificates from SAML federation metadata.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("source", help="Path to metadata XML file or URL")
    parser.add_argument(
        "--server",
        default="http://localhost:8080",
        help="TLSentinel server base URL (default: http://localhost:8080)",
    )
    parser.add_argument("--token", default="", help="Bearer token for API authentication")
    parser.add_argument("--dry-run", action="store_true", help="Parse and display certs without ingesting")

    ep_group = parser.add_argument_group("endpoint linking (optional)")
    ep_group.add_argument("--endpoint-id",   metavar="UUID", help="Link certs to an existing endpoint by ID")
    ep_group.add_argument("--endpoint-name", metavar="NAME", help="Link certs to an existing endpoint by name, or use with --create-endpoint")
    ep_group.add_argument(
        "--create-endpoint",
        action="store_true",
        help="Create a new SAML endpoint (requires --endpoint-name and --metadata-url).",
    )
    ep_group.add_argument(
        "--metadata-url", metavar="URL",
        help="Metadata URL to store on the endpoint (required when --create-endpoint and source is a local file).",
    )

    args = parser.parse_args()

    # Validate endpoint args
    if args.create_endpoint and not args.endpoint_name:
        parser.error("--create-endpoint requires --endpoint-name")
    if args.endpoint_id and args.endpoint_name:
        parser.error("--endpoint-id and --endpoint-name are mutually exclusive")

    # Load and parse
    print(f"\nParsing {args.source} …")
    try:
        root = load_xml(args.source)
    except Exception as e:
        print(f"  Error loading metadata: {e}", file=sys.stderr)
        return 1

    certs = extract_certs(root)
    if not certs:
        print("  No X.509 certificates found in metadata.")
        return 0

    print(f"  Found {len(certs)} certificate(s):\n")

    # Dry run
    if args.dry_run:
        for cert in certs:
            try:
                size = len(base64.b64decode(cert.der_b64))
            except Exception:
                size = 0
            print(f"  [{cert.use:12s}]  {cert.entity_id}  ({size} bytes DER)")
        print()
        return 0

    if not args.token:
        print("  --token is required unless using --dry-run.", file=sys.stderr)
        return 1

    # Resolve endpoint ID
    endpoint_id: str | None = args.endpoint_id

    if args.create_endpoint:
        metadata_url = args.metadata_url or (args.source if args.source.startswith("http") else None)
        if not metadata_url:
            parser.error("--create-endpoint requires --metadata-url when source is a local file")
        print(f"  Creating SAML endpoint '{args.endpoint_name}' …")
        try:
            endpoint_id = create_saml_endpoint(args.server, args.token, args.endpoint_name, metadata_url)
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

    # Ingest certs (and optionally link)
    ok_count = 0
    fail_count = 0

    for cert in certs:
        print(f"  {cert.label}")
        result = ingest_cert(args.server, args.token, cert)
        print(f"    {'✓' if result.success else '✗'} ingest  {result.message}")

        if result.success:
            ok_count += 1
            if endpoint_id:
                linked, link_msg = link_cert_to_endpoint(args.server, args.token, endpoint_id, result)
                print(f"    {'✓' if linked else '✗'} link    {link_msg}")
                if not linked:
                    fail_count += 1
        else:
            fail_count += 1

    print(f"\nDone: {ok_count} ingested, {fail_count} failed.\n")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
