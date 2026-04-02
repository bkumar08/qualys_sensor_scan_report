# Qualys Drift Container Vulnerability Report Generator

A Python script that queries the **Qualys Gateway Container Security API** to find all containers flagged as **drift** (`isDrift:true`), fetches detailed vulnerability data for each, and produces a timestamped **CSV report**.

## Features

- **Automatic token generation** from Qualys username/password, with fallback to a pre-existing bearer token
- **Paginated container listing** with deduplication to handle unreliable API pagination
- **Parallel detail fetching** — processes container details concurrently (configurable workers) per page batch
- **Incremental CSV writing** — rows written to disk after each page to keep memory usage low (safe for 2M+ containers)
- **Graceful error handling** — clean messages for invalid tokens, network issues, or empty results

## Prerequisites

- Python 3.7+
- `requests` library

```bash
pip install requests
```

## Authentication

The script supports two authentication methods, checked in order:

### Option A — Username & Password (recommended)

Generates a fresh bearer token on each run via `POST /auth`.

```bash
export QUALYS_USERNAME="your_username"
export QUALYS_PASSWORD="your_password"
```

### Option B — Pre-existing Bearer Token

Falls back to this if username/password are not set.

```bash
export QUALYS_BEARER_TOKEN="eyJ..."
```

## Usage

```bash
python3 drift_container_vul_report.py
```

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `QUALYS_USERNAME` | — | Qualys platform username |
| `QUALYS_PASSWORD` | — | Qualys platform password |
| `QUALYS_BEARER_TOKEN` | — | Pre-existing bearer token (fallback) |
| `OUTPUT_DIR` | Current directory | Directory where the CSV report is saved |

## Output

The script generates a CSV file named:

```
drift_container_vul_report_YYYYMMDD_HHMMSS.csv
```

### CSV Columns

| Column | Description |
|--------|-------------|
| `containerId` | Short container ID |
| `container_name` | Container name |
| `imageSha` | Image SHA digest |
| `drift.category` | Drift category (e.g., Vulnerability, Software) |
| `drift.reason` | Drift reason (e.g., New) |
| `drift.software` | Drift software details |
| `vulnerability.qid` | Qualys vulnerability QID |
| `vulnerability.title` | Vulnerability title |
| `vulnerability.qdsScore` | Qualys Detection Score |
| `vulnerability.reason` | Vulnerability drift reason |
| `vulnerability.cveids` | Associated CVE IDs |

> **Note:** One row per drift vulnerability per container. A container with 5 drift vulnerabilities produces 5 rows sharing the same `containerId`.

## Configuration

Defaults can be modified at the top of the script:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `GATEWAY_HOST` | `https://gateway.qg1.apps.qualys.com` | Qualys gateway URL |
| `RAW_FILTER` | `isDrift:true` | QQL filter for container list API |
| `PAGE_SIZE` | `250` | Containers fetched per API page |
| `MAX_WORKERS` | `10` | Concurrent threads for detail API calls |

## Example Output

```
Generating token from QUALYS_USERNAME / QUALYS_PASSWORD ...
Token generated successfully.
isDrift container count: 862
Fetching drift containers and processing per page ...
  Fetching container list page 1 ...
    → 250 new containers on page 1 (total: 250)
    → fetching details for 250 containers (parallel, workers=10) ...
    → wrote 312 rows to CSV (total rows: 312)
  Fetching container list page 2 ...
    ...

Done. 862 containers → 1024 CSV rows → /Users/you/drift_container_vul_report_20260402_103000.csv
```

## License

Internal use — Qualys Container Security team.
