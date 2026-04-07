#!/usr/bin/env python3
"""
create_scanner.py

Create a scanner token in TLSentinel. The raw token is printed once on
creation and never retrievable again — save it immediately.

Usage:
    python create_scanner.py --server <url> --token <admin-token> --name <scanner-name>

Examples:
    TOKEN=$(python login.py --server https://tlsentinel.example.com --username admin)

    # Create a scanner with defaults (interval 3600s, concurrency 5)
    python create_scanner.py \\
        --server https://tlsentinel.example.com --token "$TOKEN" \\
        --name "prod-scanner-01"

    # Create a scanner with custom interval and concurrency
    python create_scanner.py \\
        --server https://tlsentinel.example.com --token "$TOKEN" \\
        --name "prod-scanner-01" \\
        --interval 1800 --concurrency 10
"""

import argparse
import json
import sys
import urllib.error
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a TLSentinel scanner token.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--server", default="http://localhost:8080",
                        help="TLSentinel server base URL (default: http://localhost:8080)")
    parser.add_argument("--token", required=True, help="Bearer token for API authentication")
    parser.add_argument("--name", required=True, help="Name for the new scanner")
    parser.add_argument("--interval", type=int, default=3600,
                        help="Scan interval in seconds (default: 3600)")
    parser.add_argument("--concurrency", type=int, default=5,
                        help="Scan concurrency (default: 5)")
    args = parser.parse_args()

    url = f"{args.server.rstrip('/')}/api/v1/scanners"
    payload = json.dumps({
        "name": args.name,
        "scanIntervalSeconds": args.interval,
        "scanConcurrency": args.concurrency,
    }).encode()

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {args.token}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())

        print(f"\n  Scanner created successfully\n")
        print(f"  ID          {body['id']}")
        print(f"  Name        {body['name']}")
        print(f"  Interval    {args.interval}s")
        print(f"  Concurrency {args.concurrency}")
        print(f"\n  Scanner Token (save this — it will not be shown again):")
        print(f"\n    {body['token']}\n")
        return 0

    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="replace")
        print(f"  Error: HTTP {e.code}: {msg}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"  Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
