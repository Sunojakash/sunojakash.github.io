#!/usr/bin/env python3
"""Fetch a bounded OpenCVE snapshot for the static CVE dashboard."""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = ROOT / "data" / "cves.json"
API_URL = "https://app.opencve.io/api/v2/cves"
PAGE_SIZE = 100


def fetch_json(url: str, token: str) -> dict:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "AkashSunojPortfolioCveSync/1.0",
        },
    )
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def first_value(value, default=""):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


def normalize(item: dict) -> dict:
    cve_id = item.get("id") or item.get("cve_id") or item.get("name") or ""
    cvss = item.get("cvss") or item.get("cvss_score")
    severity = item.get("severity") or item.get("cvss_severity") or "UNKNOWN"
    description = item.get("description") or item.get("summary") or ""
    references = item.get("references") or []
    vendor_url = ""
    for reference in references:
        url = reference.get("url") if isinstance(reference, dict) else reference
        if isinstance(url, str) and url.startswith(("https://", "http://")):
            vendor_url = url
            break

    return {
        "cve_id": cve_id,
        "asset_id": cve_id,
        "asset_name": first_value(item.get("product"), "OpenCVE catalog"),
        "vendor": first_value(item.get("vendor")),
        "product": first_value(item.get("product")),
        "version": first_value(item.get("version"), "See affected versions"),
        "severity": str(severity).upper(),
        "cvss": cvss,
        "known_exploited": bool(item.get("known_exploited", False)),
        "epss": item.get("epss"),
        "fixed_version": item.get("fixed_version") or "",
        "patch_available": bool(item.get("patch_available", False)),
        "vendor_url": vendor_url,
        "source": "OpenCVE",
        "description": description,
        "last_modified": item.get("updated_at") or item.get("last_modified") or item.get("modified"),
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
    }


def main() -> int:
    token = os.environ.get("OPENCVE_API_TOKEN", "").strip()
    if not token:
        print("OPENCVE_API_TOKEN is not configured", file=sys.stderr)
        return 2

    query = urlencode({"page_size": PAGE_SIZE, "ordering": "-updated_at"})
    payload = fetch_json(f"{API_URL}?{query}", token)
    raw_items = payload.get("results") or payload.get("data") or payload.get("vulnerabilities") or []
    findings = [normalize(item) for item in raw_items if isinstance(item, dict) and (item.get("id") or item.get("cve_id"))]

    output = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "source": "OpenCVE API v2",
        "asset_count": len({item["asset_id"] for item in findings}),
        "vulnerable_asset_count": len({item["asset_id"] for item in findings}),
        "findings": findings,
    }
    OUTPUT_PATH.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(findings)} OpenCVE findings to {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
