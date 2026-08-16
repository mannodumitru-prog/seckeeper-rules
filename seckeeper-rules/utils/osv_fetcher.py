#!/usr/bin/env python3
"""OSV单包查询诊断工具；不负责写入SecKeeper规则库。"""

import argparse
import json
import requests


def fetch_osv_vulnerabilities(package_name: str, ecosystem: str = "Debian"):
    response = requests.post(
        "https://api.osv.dev/v1/query",
        json={"package": {"name": package_name, "ecosystem": ecosystem}},
        timeout=20,
    )
    response.raise_for_status()
    return response.json().get("vulns", [])


def main() -> int:
    parser = argparse.ArgumentParser(description="Query OSV without modifying repository files")
    parser.add_argument("package", nargs="?", default="openssl")
    parser.add_argument("--ecosystem", default="Debian")
    args = parser.parse_args()
    vulnerabilities = fetch_osv_vulnerabilities(args.package, args.ecosystem)
    print(f"Found {len(vulnerabilities)} OSV records for {args.ecosystem}/{args.package}.")
    if vulnerabilities:
        print(json.dumps(vulnerabilities[0], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
