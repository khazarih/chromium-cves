# AI Agent Usage Guide

This guide explains how AI agents can use the Chromium CVE Patch Pattern Database for vulnerability research, code review, and security analysis.

## Quick Start

```python
import chromadb

# Connect to ChromaDB
client = chromadb.HttpClient(host="localhost", port=8001)

# Get collections
cves = client.get_collection("chromium_cves")
patches = client.get_collection("chromium_patches")
```

## Collections Overview

| Collection | Records | Purpose |
|------------|---------|---------|
| `chromium_cves` | ~3,500 | CVE descriptions, severity, metadata |
| `chromium_patches` | ~400 | Patched code with vulnerable/fixed code |

## Querying CVEs

### Semantic Search

```python
# Find CVEs related to sandbox escape
results = cves.query(
    query_texts=["sandbox escape via renderer process"],
    n_results=10
)

# Find CVEs in a specific component
results = cves.query(
    query_texts=["heap buffer overflow in V8 JavaScript engine"],
    n_results=5
)
```

### Filtered Search

```python
# Only CRITICAL severity
results = cves.query(
    query_texts=["remote code execution"],
    n_results=10,
    where={"severity": "CRITICAL"}
)

# Only HIGH severity in Chrome
results = cves.query(
    query_texts=["use after free"],
    n_results=10,
    where={
        "severity": "HIGH",
        "products": {"$contains": "Chrome"}
    }
)
```

### Available Metadata Fields

| Field | Type | Filter Example |
|-------|------|----------------|
| `severity` | string | `{"severity": "CRITICAL"}` |
| `problem_types` | list | `{"problem_types": {"$contains": "Heap buffer overflow"}}` |
| `products` | list | `{"products": {"$contains": "Chrome"}}` |
| `vendors` | list | `{"vendors": {"$contains": "Google"}}` |
| `date_published` | string | ISO timestamp |
| `bug_ids` | list | Chromium bug tracker IDs |
| `commit_hashes` | list | Resolved fix commits |

## Querying Patches

### Semantic Code Search

```python
# Find similar vulnerability patterns
results = patches.query(
    query_texts=["use after free in renderer IPC handler"],
    n_results=10
)

# Find fixes for specific vulnerability types
results = patches.query(
    query_texts=["bounds check missing before array access"],
    n_results=5
)
```

### Filtered Code Search

```python
# Only C++ patches with HIGH severity
results = patches.query(
    query_texts=["heap buffer overflow"],
    n_results=10,
    where={
        "language": "cc",
        "severity": "HIGH"
    }
)

# Find patches in specific component
results = patches.query(
    query_texts=["sandbox escape"],
    n_results=5,
    where={"file_path": {"$contains": "content/browser"}}
)
```

### Available Metadata Fields

| Field | Type | Filter Example |
|-------|------|----------------|
| `severity` | string | `{"severity": "CRITICAL"}` |
| `language` | string | `{"language": "cc"}` |
| `problem_types` | list | `{"problem_types": {"$contains": "Use after free"}}` |
| `file_path` | string | `{"file_path": {"$contains": "content/renderer"}}` |
| `cve_id` | string | `{"cve_id": "CVE-2024-1234"}` |
| `commit_hash` | string | Full 40-char hash |

## Understanding Results

### CVE Result Structure

```json
{
  "id": "CVE-2024-1234",
  "document": "Heap buffer overflow in ANGLE...",
  "metadata": {
    "severity": "HIGH",
    "problem_types": ["Heap buffer overflow"],
    "products": ["Chrome"],
    "vendors": ["Google"],
    "bug_ids": ["123456"],
    "commit_hashes": ["abc123..."],
    "date_published": "2024-01-15T10:00:00Z"
  }
}
```

### Patch Result Structure

```json
{
  "id": "CVE-2024-1234::abc123def456::content/renderer/render_widget.cc",
  "document": "CVE: CVE-2024-1234 | Heap buffer overflow | Severity: HIGH\n\nHeap buffer overflow in ANGLE...\n\nCommit: Fix bounds checking in RenderWidget\n\n--- Vulnerable code:\n[code]\n\n+++ Patched code:\n[code]",
  "metadata": {
    "cve_id": "CVE-2024-1234",
    "severity": "HIGH",
    "problem_types": ["Heap buffer overflow"],
    "commit_message": "Fix bounds checking in RenderWidget\n\nThis patch adds proper bounds validation before...\n\nBug: 123456\nChange-Id: I1234...",
    "cve_description": "Heap buffer overflow in ANGLE...",
    "file_path": "content/renderer/render_widget.cc",
    "language": "cc",
    "vulnerable_code": "int size = Read32(buffer);\nchar* data = buffer + offset;",
    "patched_code": "uint32_t size = Read32(buffer);\nif (size > buffer_size - offset) return;\nchar* data = buffer + offset;"
  }
}
```

## Use Cases

### 1. Vulnerability Pattern Analysis

Find similar vulnerability patterns across different CVEs:

```python
# Find all use-after-free patterns in renderer
results = patches.query(
    query_texts=["use after free in renderer process IPC"],
    n_results=20,
    where={"severity": {"$in": ["CRITICAL", "HIGH"]}}
)

# Analyze common patterns
for patch in results["metadatas"][0]:
    print(f"{patch['cve_id']}: {patch['file_path']}")
    print(f"  Type: {patch['problem_types']}")
    print(f"  Fix: {patch['commit_message'][:100]}...")
```

### 2. Code Review Assistance

Check if new code has similar patterns to known vulnerabilities:

```python
# Search for similar code patterns
suspect_code = """
void ProcessData(char* buffer, int length) {
    int offset = ReadInt(buffer);
    char* data = buffer + offset;  // Potential OOB access
    memcpy(dest, data, length);
}
"""

results = patches.query(
    query_texts=[suspect_code],
    n_results=5,
    where={"language": "cc"}
)

# Check if similar vulnerable patterns exist
for i, patch in enumerate(results["metadatas"][0]):
    if results["distances"][0][i] < 0.5:  # Close match
        print(f"Similar to: {patch['cve_id']}")
        print(f"Vulnerable code: {patch['vulnerable_code'][:100]}...")
        print(f"Fix: {patch['patched_code'][:100]}...")
```

### 3. Security Research

Find all vulnerabilities in a specific component:

```python
# Find all CVEs in content/renderer
results = cves.query(
    query_texts=["vulnerability in renderer"],
    n_results=50,
    where={"products": {"$contains": "Chrome"}}
)

# Get patches for these CVEs
for cve_id in results["ids"][0]:
    patches_result = patches.query(
        query_texts=["vulnerability"],
        n_results=5,
        where={"cve_id": cve_id}
    )
    # Analyze the patches
```

### 4. Severity-Based Analysis

Focus on most critical vulnerabilities:

```python
# Get all CRITICAL CVEs
critical_cves = cves.query(
    query_texts=["remote code execution sandbox escape"],
    n_results=100,
    where={"severity": "CRITICAL"}
)

# Get their patches
for cve_id in critical_cves["ids"][0][:10]:
    patches_result = patches.query(
        query_texts=["vulnerability fix"],
        n_results=3,
        where={"cve_id": cve_id}
    )
    # Deep analysis of critical fixes
```

### 5. Language-Specific Analysis

Find vulnerabilities in specific programming languages:

```python
# Find C++ vulnerabilities
cpp_patches = patches.query(
    query_texts=["memory corruption"],
    n_results=20,
    where={"language": "cc"}
)

# Find JavaScript vulnerabilities
js_patches = patches.query(
    query_texts=["type confusion"],
    n_results=20,
    where={"language": "js"}
)
```

## Best Practices

### 1. Start Broad, Then Narrow

```python
# Bad: Too specific
results = cves.query(
    query_texts=["CVE-2024-1234 heap buffer overflow in ANGLE renderer process"],
    n_results=5
)

# Good: Start broad, filter results
results = cves.query(
    query_texts=["heap buffer overflow"],
    n_results=20,
    where={"severity": "HIGH"}
)
```

### 2. Use Metadata Filters

```python
# Bad: Semantic search only
results = patches.query(
    query_texts=["use after free in Chrome renderer"],
    n_results=10
)

# Good: Combine semantic search with filters
results = patches.query(
    query_texts=["use after free"],
    n_results=10,
    where={
        "severity": {"$in": ["CRITICAL", "HIGH"]},
        "language": "cc"
    }
)
```

### 3. Understand Distance Scores

- **Distance < 0.3**: Very similar vulnerability pattern
- **Distance 0.3-0.5**: Related vulnerability type
- **Distance 0.5-0.7**: Similar component or context
- **Distance > 0.7**: Weak match, review manually

### 4. Combine CVE and Patch Data

```python
# Get CVE details
cve_result = cves.get(ids=["CVE-2024-1234"])
print(f"Description: {cve_result['documents'][0]}")
print(f"Severity: {cve_result['metadatas'][0]['severity']}")

# Get related patches
patch_result = patches.query(
    query_texts=["vulnerability fix"],
    n_results=5,
    where={"cve_id": "CVE-2024-1234"}
)

# Analyze the fix
for patch in patch_result["metadatas"][0]:
    print(f"File: {patch['file_path']}")
    print(f"Vulnerable code:\n{patch['vulnerable_code']}")
    print(f"Patched code:\n{patch['patched_code']}")
```

### 5. Use Problem Types for Pattern Matching

```python
# Find all use-after-free vulnerabilities
uaf_patches = patches.query(
    query_texts=["memory corruption"],
    n_results=50,
    where={"problem_types": {"$contains": "Use after free"}}
)

# Find all buffer overflow vulnerabilities
bof_patches = patches.query(
    query_texts=["bounds checking"],
    n_results=50,
    where={"problem_types": {"$contains": "buffer overflow"}}
)
```

## Example Workflows

### Workflow 1: Analyze New Vulnerability Report

```python
# Input: New vulnerability report
report = """
Heap buffer overflow in WebAssembly parser allowed remote attacker 
to corrupt heap memory via crafted WebAssembly module.
"""

# 1. Find similar CVEs
similar_cves = cves.query(
    query_texts=[report],
    n_results=5,
    where={"severity": {"$in": ["CRITICAL", "HIGH"]}}
)

# 2. Get patches for similar CVEs
for cve_id in similar_cves["ids"][0]:
    patches_result = patches.query(
        query_texts=[report],
        n_results=3,
        where={"cve_id": cve_id}
    )
    
    # 3. Analyze fixes
    for patch in patches_result["metadatas"][0]:
        print(f"Similar CVE: {cve_id}")
        print(f"Fix location: {patch['file_path']}")
        print(f"Vulnerable code:\n{patch['vulnerable_code']}")
        print(f"Fix applied:\n{patch['patched_code']}")
```

### Workflow 2: Code Review for Vulnerabilities

```python
# Input: Code to review
code_to_review = """
void ProcessMessage(const char* data, size_t length) {
    int offset = *reinterpret_cast<const int*>(data);
    char* payload = const_cast<char*>(data) + offset;
    ProcessPayload(payload, length - offset);
}
"""

# 1. Find similar vulnerable patterns
similar_patches = patches.query(
    query_texts=[code_to_review],
    n_results=10,
    where={"language": "cc"}
)

# 2. Check for matches
for i, patch in enumerate(similar_patches["metadatas"][0]):
    distance = similar_patches["distances"][0][i]
    if distance < 0.5:
        print(f"⚠️  Potential vulnerability similar to {patch['cve_id']}")
        print(f"   Vulnerable pattern: {patch['vulnerable_code'][:200]}...")
        print(f"   Fix applied: {patch['patched_code'][:200]}...")
        print()
```

### Workflow 3: Generate Security Report

```python
# Generate report for a component
component = "content/renderer"

# 1. Find all CVEs in component
component_cves = cves.query(
    query_texts=[f"vulnerability in {component}"],
    n_results=100,
    where={"products": {"$contains": "Chrome"}}
)

# 2. Analyze severity distribution
severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
for meta in component_cves["metadatas"][0]:
    severity_count[meta["severity"]] += 1

# 3. Find common vulnerability types
type_count = {}
for meta in component_cves["metadatas"][0]:
    for pt in meta.get("problem_types", []):
        type_count[pt] = type_count.get(pt, 0) + 1

# 4. Generate report
print(f"Security Report for {component}")
print(f"Total CVEs: {len(component_cves['ids'][0])}")
print(f"Severity Distribution: {severity_count}")
print(f"Common Vulnerability Types: {type_count}")
```

## Limitations

1. **Coverage**: Only ~3,500 Chromium CVEs (filtered from ~359K total)
2. **Patches**: Only ~400 patches extracted (needs full resolver/extractor run)
3. **Freshness**: Data depends on cvelistV5 updates and gitiles API availability
4. **Semantic Search**: Based on code similarity, not exact vulnerability matching

## Contributing

To improve coverage:

```bash
# Run resolver to map more bug IDs to commits
python resolver.py

# Run extractor to get more patches
python extractor.py
```

## Support

For issues or questions:
- Check the README.md for setup instructions
- Review DESIGN.md for architecture details
- Open an issue on GitHub
