#!/usr/bin/env python3
"""
login.py

Authenticate against the TLSentinel API and print a bearer token.
The token can be captured in a shell variable for use with other scripts.

Usage:
    python login.py [options]

Examples:
    # Prompt for password
    python login.py --server https://tlsentinel.example.com --username admin

    # Capture token into a shell variable
    TOKEN=$(python login.py --server https://tlsentinel.example.com --username admin --password secret)

    # Use the token with another script
    TOKEN=$(python login.py --server https://tlsentinel.example.com --username admin)
    python import_cert.py partner.pem --server https://tlsentinel.example.com --token "$TOKEN"
"""

import argparse
import getpass
import json
import sys
import urllib.error
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authenticate with TLSentinel and print a bearer token.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--server", default="http://localhost:8080",
                        help="TLSentinel server base URL (default: http://localhost:8080)")
    parser.add_argument("--username", required=True, help="Username")
    parser.add_argument("--password", default=None,
                        help="Password (omit to be prompted securely)")
    args = parser.parse_args()

    password = args.password or getpass.getpass(f"Password for {args.username}: ")

    url = f"{args.server.rstrip('/')}/api/v1/auth/login"
    payload = json.dumps({"username": args.username, "password": password}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
            token = body.get("token", "")
            if not token:
                print("Error: server returned no token.", file=sys.stderr)
                return 1
            # Print only the token so it can be captured cleanly
            print(token)
            return 0
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="replace")
        print(f"Error: HTTP {e.code}: {msg}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
