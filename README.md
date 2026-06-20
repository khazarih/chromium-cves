# chromium-cves

Collects Chromium ecosystem CVEs, resolves them to fix commits, extracts patched source code patterns, and stores everything in ChromaDB for semantic search by LLM models during vulnerability research.

## Architecture

```
cvelistV5 (git submodule)
    │
    ▼
┌──────────┐    ┌──────────┐    ┌──────────┐
│ collector │───▶│ resolver │───▶│extractor │
│           │    │          │    │          │
│ CVE JSON  │    │bug→commit│   │ commit   │
│ → Chroma  │    │via gitiles│  │ → code   │
└──────────┘    └──────────┘    └──────────┘
                                      │
                                      ▼
                                 ┌──────────┐
                                 │ ChromaDB │
                                 └──────────┘
                                      │
                                      ▼
                                 ┌──────────┐
                                 │  query   │
                                 └──────────┘
```

**Four independent stages**, each incremental (skips already-processed data):

| Stage | Script | What it does |
|-------|--------|-------------|
| Collect | `collector.py` | Parses cvelistV5, filters Chromium CVEs, stores metadata in ChromaDB |
| Resolve | `resolver.py` | Maps bug IDs to fix commits via gitiles API |
| Extract | `extractor.py` | Fetches commit diffs, extracts patched source code |
| Query | `query.py` | Semantic search CLI for CVEs and patches |

## Prerequisites

- Python 3.14+
- Docker (for ChromaDB)
- [uv](https://docs.astral.sh/uv/) (package manager)

## Setup

```bash
# Clone
git clone git@github.com:khazarih/chromium-cves.git
cd chromium-cves

# Clone cvelistV5 data (required)
git clone https://github.com/CVEProject/cvelistV5.git

# Install dependencies
uv sync

# Configure
cp env.example .env

# Start ChromaDB
docker compose up -d
```

## Usage

Run each stage in order. All stages are incremental — safe to re-run.

```bash
# 1. Collect CVEs (~5900 Chromium CVEs)
python collector.py

# 2. Resolve bug IDs → commit hashes (API rate-limited, takes a while)
python resolver.py

# 3. Extract patched code from commits
python extractor.py

# 4. Query
python query.py cves "sandbox escape" -n 5
python query.py patches "use after free" --lang cpp -n 3
python query.py show CVE-2022-3075
```

## ChromaDB Schema

### `chromium_cves` collection

CVE descriptions embedded for semantic search.

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | CVE ID |
| `document` | string | CVE description (embedded) |
| `metadata.date_published` | string | ISO timestamp |
| `metadata.state` | string | `PUBLISHED` |
| `metadata.vendors` | list | e.g. `["Google"]` |
| `metadata.products` | list | e.g. `["Chrome"]` |
| `metadata.references` | list | Reference URLs |
| `metadata.bug_ids` | list | Chromium bug tracker IDs |
| `metadata.commit_hashes` | list | Resolved fix commits |
| `metadata.problem_types` | list | e.g. `["Heap buffer overflow", "Use after free"]` |
| `metadata.severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |

### `chromium_patches` collection

Patched source code embedded with vulnerability context for semantic search.

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | `{cve_id}::{hash}::{file_path}` |
| `document` | string | CVE info + commit message + vulnerable/patched code (embedded) |
| `metadata.cve_id` | string | Parent CVE |
| `metadata.commit_hash` | string | Fix commit hash |
| `metadata.file_path` | string | Source file path |
| `metadata.language` | string | `cpp`, `js`, `py`, etc. |
| `metadata.severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| `metadata.problem_types` | list | Vulnerability types from NVD |
| `metadata.cve_description` | string | Full CVE description |
| `metadata.commit_message` | string | Git commit message explaining the fix |
| `metadata.vulnerable_code` | string | Removed lines (`-` in diff) — the vulnerable code |
| `metadata.patched_code` | string | Added lines (`+` in diff) — the fixed code |

## Configuration

All settings via environment variables (`.env`):

| Variable | Default | Description |
|----------|---------|-------------|
| `cvelistV5_path` | `./cvelistV5` | Path to cvelistV5 repo |
| `CHROMA_HOST` | `localhost` | ChromaDB host |
| `CHROMA_PORT` | `8001` | ChromaDB port |
| `CHROMA_CVES_COLLECTION` | `chromium_cves` | CVE collection name |
| `CHROMA_PATCHES_COLLECTION` | `chromium_patches` | Patches collection name |

## Project Structure

```
.
├── collector.py        # Stage 1: CVE collection
├── resolver.py         # Stage 2: Bug → commit resolution
├── extractor.py        # Stage 3: Patch extraction
├── query.py            # Stage 4: Semantic search CLI
├── db.py               # ChromaDB interface
├── config.py           # Environment config
├── docker-compose.yml  # ChromaDB container
├── DESIGN.md           # Detailed architecture docs
├── pyproject.toml
├── .env
└── cvelistV5/          # CVE data (separate clone)
```
