#!/usr/bin/env python3
"""
Qualys Container Security - Drift Container Vulnerability Report Generator

Fetches containers with isDrift:true from the Qualys CSAPI, retrieves detail
for each container SHA, and produces a timestamped CSV report.

Usage:
    export QUALYS_USERNAME="<user>" QUALYS_PASSWORD="<pass>"
    python3 drift_container_vul_report.py

    # Or with a pre-existing bearer token:
    export QUALYS_BEARER_TOKEN="<your-token>"
    python3 drift_container_vul_report.py
"""

import csv
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests

# ─── Configuration ───────────────────────────────────────────────────────────
GATEWAY_HOST = "https://gateway.qg1.apps.qualys.com"
BASE_URL = f"{GATEWAY_HOST}/csapi/v1.3"
RAW_FILTER = "isDrift:true"
PAGE_SIZE = 250
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", os.getcwd())

MAX_WORKERS = 10


def generate_token(username, password):
    """POST /auth to generate a bearer token from credentials."""
    url = f"{GATEWAY_HOST}/auth"
    data = {
        "username": username,
        "password": password,
        "token": "true",
        "permissions": "true",
    }
    resp = requests.post(url, data=data, timeout=60, verify=True)
    resp.raise_for_status()
    return resp.text.strip()


def get_token():
    """
    1) If QUALYS_USERNAME & QUALYS_PASSWORD are set, generate a fresh token.
    2) Otherwise fall back to QUALYS_BEARER_TOKEN env var.
    """
    username = os.environ.get("QUALYS_USERNAME", "").strip()
    password = os.environ.get("QUALYS_PASSWORD", "").strip()

    if username and password:
        print("Generating token from QUALYS_USERNAME / QUALYS_PASSWORD ...")
        try:
            token = generate_token(username, password)
            print("Token generated successfully.")
            return token
        except requests.HTTPError as exc:
            print(f"ERROR: Token generation failed (HTTP {exc.response.status_code}).")
            print(f"       Check your username/password. Detail: {exc}")
            sys.exit(1)
        except requests.ConnectionError:
            print(f"ERROR: Cannot connect to {GATEWAY_HOST}/auth. Check network/VPN.")
            sys.exit(1)

    token = os.environ.get("QUALYS_BEARER_TOKEN", "").strip()
    if not token:
        print("ERROR: Provide credentials via QUALYS_USERNAME + QUALYS_PASSWORD,")
        print("       or set QUALYS_BEARER_TOKEN environment variable.")
        sys.exit(1)
    print("Using token from QUALYS_BEARER_TOKEN environment variable.")
    return token


def build_headers(token):
    return {
        "accept": "application/json",
        "Authorization": f"Bearer {token}",
    }


# ─── Pagination helpers ─────────────────────────────────────────────────────
def fetch_drift_count(token):
    """Quick call to /containers to get total isDrift container count."""
    headers = build_headers(token)
    resp = requests.get(
        f"{BASE_URL}/containers",
        headers=headers,
        params={"filter": RAW_FILTER, "pageSize": 1},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json().get("count", "unknown")


def fetch_page(token, url, params, next_url, page):
    """
    Fetch a single page from the container list API.
    Returns (data_list, next_url_or_None).
    """
    headers = build_headers(token)
    print(f"  Fetching container list page {page} ...")
    resp = requests.get(
        next_url or url,
        headers=headers,
        params=params,
        timeout=120,
    )
    resp.raise_for_status()

    data = resp.json().get("data", [])

    # Parse link header for next page URL
    link_header = resp.headers.get("Link") or resp.headers.get("link")
    parsed_next = None
    if link_header and "rel=next" in link_header:
        start = link_header.find("<") + 1
        end = link_header.find(">")
        parsed_next = link_header[start:end]

    return data, parsed_next


def process_page_containers(containers, token):
    """
    Fetch container details in parallel for a batch of containers.
    Returns list of CSV row dicts.
    """
    rows = []

    def _fetch_and_build(container):
        sha = container.get("sha", "")
        name = container.get("name", "")
        if not sha:
            return []
        try:
            detail = fetch_container_detail(sha, token)
            return build_rows(detail)
        except requests.HTTPError as exc:
            print(f"    ⚠ HTTP error for {sha[:12]} ({name}): {exc}")
        except Exception as exc:
            print(f"    ⚠ Unexpected error for {sha[:12]} ({name}): {exc}")
        return []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(_fetch_and_build, c): c for c in containers}
        for future in as_completed(futures):
            rows.extend(future.result())

    return rows


# ─── Container detail ────────────────────────────────────────────────────────
def fetch_container_detail(sha, token):
    """GET /containers/{sha} and return parsed JSON."""
    headers = build_headers(token)
    url = f"{BASE_URL}/containers/{sha}"
    resp = requests.get(url, headers=headers, timeout=120)
    resp.raise_for_status()
    return resp.json()


# ─── CSV row builder ─────────────────────────────────────────────────────────
CSV_COLUMNS = [
    "containerId",
    "container_name",
    "imageSha",
    "drift.category",
    "drift.reason",
    "drift.software",
    "vulnerability.qid",
    "vulnerability.title",
    "vulnerability.qdsScore",
    "vulnerability.reason",
    "vulnerability.cveids",
]


def list_to_str(val):
    """Convert a list to a pipe-delimited string; return '' for empty/None."""
    if not val:
        return ""
    return " | ".join(str(v) for v in val)


def build_rows(detail):
    """
    Given one container-detail JSON, return a list of CSV row dicts.
    One row per drift vulnerability; if there are no drift vulnerabilities,
    still emit one row with the container-level fields.
    """
    container_id = detail.get("containerId", "")
    container_name = detail.get("name", "")
    image_sha = detail.get("imageSha", "")

    drift = detail.get("drift") or {}
    drift_category = list_to_str(drift.get("category"))
    drift_reason = list_to_str(drift.get("reason"))
    drift_software_list = drift.get("software") or []
    drift_software = list_to_str(
        [f"{s.get('name', '')}:{s.get('version', '')}" for s in drift_software_list]
        if isinstance(drift_software_list, list) and drift_software_list and isinstance(drift_software_list[0], dict)
        else drift_software_list
    )

    drift_vulns = drift.get("vulnerability") or []
    if not drift_vulns:
        return [
            {
                "containerId": container_id,
                "container_name": container_name,
                "imageSha": image_sha,
                "drift.category": drift_category,
                "drift.reason": drift_reason,
                "drift.software": drift_software,
                "vulnerability.qid": "",
                "vulnerability.title": "",
                "vulnerability.qdsScore": "",
                "vulnerability.reason": "",
                "vulnerability.cveids": "",
            }
        ]

    rows = []
    for vuln in drift_vulns:
        rows.append(
            {
                "containerId": container_id,
                "container_name": container_name,
                "imageSha": image_sha,
                "drift.category": drift_category,
                "drift.reason": drift_reason,
                "drift.software": drift_software,
                "vulnerability.qid": vuln.get("qid", ""),
                "vulnerability.title": vuln.get("title", ""),
                "vulnerability.qdsScore": vuln.get("qdsScore", ""),
                "vulnerability.reason": vuln.get("reason", ""),
                "vulnerability.cveids": list_to_str(vuln.get("cveids")),
            }
        )
    return rows


# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    token = get_token()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"drift_container_vul_report_{timestamp}.csv"
    csv_path = os.path.join(OUTPUT_DIR, csv_filename)

    url = f"{BASE_URL}/containers/list"
    params = {"filter": RAW_FILTER, "limit": PAGE_SIZE}
    seen_shas = set()
    next_url = None
    page = 1
    total_containers = 0
    total_rows = 0
    header_written = False

    try:
        drift_count = fetch_drift_count(token)
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        print(f"ERROR: Failed to reach Qualys API (HTTP {status}).")
        print(f"       Check that QUALYS_BEARER_TOKEN is valid and not expired.")
        print(f"       Detail: {exc}")
        sys.exit(1)
    except requests.ConnectionError as exc:
        print(f"ERROR: Cannot connect to {BASE_URL}. Check network/VPN.")
        sys.exit(1)

    print(f"isDrift container count: {drift_count}")
    if drift_count == 0:
        print("No drift containers found. Nothing to report.")
        sys.exit(0)
    print("Fetching drift containers and processing per page ...")

    while True:
        # Fetch one page
        data, parsed_next = fetch_page(token, url, params, next_url, page)

        if not data:
            print(f"    → no data on page {page}, stopping.")
            break

        # Deduplicate using seen SHAs
        new_data = [c for c in data if c.get("sha") not in seen_shas]
        if not new_data:
            print(f"    → all {len(data)} containers on page {page} already seen, stopping.")
            break

        for c in new_data:
            seen_shas.add(c.get("sha"))
        total_containers += len(new_data)
        print(f"    → {len(new_data)} new containers on page {page} (total: {total_containers})")

        # Process this page's containers in parallel
        print(f"    → fetching details for {len(new_data)} containers (parallel, workers={MAX_WORKERS}) ...")
        page_rows = process_page_containers(new_data, token)
        total_rows += len(page_rows)

        # Append rows to CSV incrementally
        with open(csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            if not header_written:
                writer.writeheader()
                header_written = True
            writer.writerows(page_rows)
        print(f"    → wrote {len(page_rows)} rows to CSV (total rows: {total_rows})")

        # Stop if fewer results than page size (last page)
        if len(data) < PAGE_SIZE:
            break

        next_url = parsed_next
        if not next_url:
            break

        page += 1
        time.sleep(0.25)

    print(f"\nDone. {total_containers} containers → {total_rows} CSV rows → {csv_path}")


if __name__ == "__main__":
    main()
