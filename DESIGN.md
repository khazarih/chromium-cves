# Chromium CVE Patch Pattern Database

## Overview

A pipeline that collects Chromium CVEs, resolves them to fix commits, extracts patched code patterns, and stores everything in ChromaDB for semantic search by LLM models during vulnerability research.

## Architecture

```mermaid
graph TD
    subgraph "Data Source"
        A[cvelistV5<br/>CVE JSON files]
    end

    subgraph "Pipeline"
        B[collector.py<br/>Filter & Store CVEs]
        C[resolver.py<br/>Bug ID → Commit Hash]
        D[extractor.py<br/>Extract Patched Code]
    end

    subgraph "Storage"
        E[(ChromaDB<br/>2 Collections)]
        F[chromium_cves<br/>CVE descriptions + severity]
        G[chromium_patches<br/>Code + context]
    end

    subgraph "Query Interface"
        H[query.py<br/>Semantic Search CLI]
    end

    A -->|Walk directories| B
    B -->|Store CVE metadata| E
    E -->|Read bug_ids| C
    C -->|Query gitiles API| C
    C -->|Store commit_hashes| E
    E -->|Read commit_hashes| D
    D -->|Fetch diffs from gitiles| D
    D -->|Store patches + context| E
    E --> F
    E --> G
    E -->|Semantic search| H

    style A fill:#e1f5fe
    style E fill:#f3e5f5
    style H fill:#e8f5e9
```

### Pipeline Flow

```mermaid
flowchart LR
    subgraph "Stage 1: Collect"
        A1[Parse cvelistV5 JSON] --> A2{Is Chromium CVE?}
        A2 -->|Yes| A3[Extract metadata]
        A2 -->|No| A4[Skip]
        A3 --> A5[Infer severity]
        A5 --> A6[Store in chromium_cves]
    end

    subgraph "Stage 2: Resolve"
        B1[Get CVEs with bug_ids] --> B2[Query gitiles API]
        B2 --> B3[Filter noise commits]
        B3 --> B4[Store commit_hashes]
    end

    subgraph "Stage 3: Extract"
        C1[Get CVEs with commits] --> C2[Fetch diff from gitiles]
        C2 --> C3[Parse unified diff]
        C3 --> C4[Extract + and - lines]
        C4 --> C5[Fetch commit message]
        C5 --> C6[Store enriched patch]
    end

    A6 --> B1
    B4 --> C1
```

## Stages

### Stage 1: Collector (`collector.py`)

Walks `cvelistV5/cves/`, filters Chromium-related CVEs, and stores metadata in ChromaDB.

**Filtering logic:**
- Description keywords: `google chrome`, `chromium`, `chrome os`, `v8`, `blink`, `skia`, `angle`, `pdfium`, `mojo`, `dawn`, `webgpu`, `omnibox`, `fedcm`, `autofill`
- Reference domains: `chromium.org`, `googlechromereleases.blogspot.com`, `crbug.com`, `chromium.googlesource.com`
- Vendor/product: Google + Chrome/Chromium/V8

**Extracted metadata:**
- `date_published`, `state`, `vendors`, `products`, `references` (URLs)
- `bug_ids` — parsed from `crbug.com/NNN`, `issues.chromium.org/issues/NNN`
- `commit_hashes` — parsed from `chromium.googlesource.com/.../+/<hash>`

**Incremental:** Queries ChromaDB for existing CVE IDs before processing.

### Stage 2: Resolver (`resolver.py`)

Maps bug IDs to Chromium commit hashes via the gitiles API.

**API:** `https://chromium.googlesource.com/chromium/src/+log?q=bug:NNNNN&format=JSON`

For each CVE with `bug_ids` but no `commit_hashes`, queries gitiles and stores resolved commits.

**Rate limiting:** 0.5s delay between requests.

### Stage 3: Extractor (`extractor.py`)

Fetches commit diffs and extracts patched source code.

**API:** `https://chromium.googlesource.com/chromium/src/+diff/<hash>%5E%21/?format=TEXT` (base64-encoded unified diff)

**Extraction:**
- Parses unified diff into per-file chunks
- Filters to source files only (`.cc`, `.cpp`, `.c`, `.h`, `.js`, `.ts`, `.py`, `.java`, `.rs`, `.go`)
- Extracts added lines (`+` lines) as the patched code
- Stores each file's patch as a separate ChromaDB entry

**Parallelism:** ThreadPoolExecutor with 5 workers.

### Stage 4: Query (`query.py`)

CLI tool for semantic search.

```bash
python query.py cves "sandbox escape" -n 5
python query.py patches "use after free in net/" --lang cpp -n 3
python query.py show CVE-2022-3075
```

## Data Flow

```mermaid
graph LR
    subgraph "Input"
        A[cvelistV5<br/>359K+ CVE files]
    end

    subgraph "Filtering"
        B[Keyword matching<br/>15 patterns]
        C[Reference domains<br/>4 domains]
        D[Vendor/product<br/>Google + Chrome]
    end

    subgraph "Enrichment"
        E[Severity inference<br/>Pattern matching]
        F[Bug ID extraction<br/>crbug.com URLs]
        G[Commit resolution<br/>gitiles API]
    end

    subgraph "Extraction"
        H[Diff parsing<br/>Unified format]
        I[Code extraction<br/>+/- lines]
        J[Context gathering<br/>Commit message]
    end

    subgraph "Storage"
        K[(ChromaDB<br/>3,510 CVEs<br/>422 patches)]
    end

    subgraph "Output"
        L[Semantic search<br/>CLI interface]
    end

    A --> B
    A --> C
    A --> D
    B --> E
    C --> F
    D --> E
    E --> G
    F --> G
    G --> H
    H --> I
    I --> J
    J --> K
    K --> L
```

### Collection: `chromium_cves`

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | CVE ID (e.g. `CVE-2022-3075`) |
| `document` | string | CVE description text (embedded) |
| `metadata.date_published` | string | ISO timestamp |
| `metadata.state` | string | e.g. `PUBLISHED` |
| `metadata.vendors` | list[string] | e.g. `["Google"]` |
| `metadata.products` | list[string] | e.g. `["Chrome"]` |
| `metadata.references` | list[string] | All reference URLs |
| `metadata.bug_ids` | list[string] | Chromium bug tracker IDs |
| `metadata.commit_hashes` | list[string] | Resolved fix commit hashes |
| `metadata.problem_types` | list[string] | e.g. `["Heap buffer overflow", "Use after free"]` |
| `metadata.severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` (inferred from description) |

### Collection: `chromium_patches`

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | `{cve_id}::{hash}::{file_path}` |
| `document` | string | CVE info + commit message + code (embedded) |
| `metadata.cve_id` | string | Parent CVE |
| `metadata.commit_hash` | string | Fix commit |
| `metadata.file_path` | string | Source file path |
| `metadata.language` | string | File extension (cpp, js, etc.) |
| `metadata.severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| `metadata.problem_types` | list[string] | Vulnerability types |
| `metadata.cve_description` | string | Full CVE description |
| `metadata.commit_message` | string | Git commit message explaining the fix |
| `metadata.vulnerable_code` | string | Removed lines (`-` in diff) — the vulnerable code |
| `metadata.patched_code` | string | Added lines (`+` in diff) — the fixed code |

## Configuration

`.env`:
```
cvelistV5_path="./cvelistV5"
CHROMA_HOST="localhost"
CHROMA_PORT="8001"
CHROMA_CVES_COLLECTION="chromium_cves"
CHROMA_PATCHES_COLLECTION="chromium_patches"
```

## Usage

```bash
# Start ChromaDB
docker compose up -d

# Run pipeline (each stage is incremental)
python collector.py    # ~5900 CVEs from cvelistV5
python resolver.py     # resolve bug IDs → commits (slow, API rate limited)
python extractor.py    # extract patched code from commits

# Query
python query.py cves "buffer overflow in renderer"
python query.py patches "use after free" --lang cpp
python query.py show CVE-2022-3075
```

## Files

| File | Purpose |
|------|---------|
| `collector.py` | Stage 1: CVE collection |
| `resolver.py` | Stage 2: Bug → commit resolution |
| `extractor.py` | Stage 3: Patch extraction |
| `query.py` | Stage 4: Semantic search CLI |
| `db.py` | Shared ChromaDB interface |
| `config.py` | Environment configuration |
| `docker-compose.yml` | ChromaDB container |
| `.env` | Local environment variables |
| `cvelistV5/` | CVE data (git submodule) |
