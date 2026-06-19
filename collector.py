from config import config
import os
import re
import json
from concurrent.futures import ProcessPoolExecutor
from db import get_existing_cve_ids, upsert_cves

PATTERNS = [
    re.compile(rf"\b{re.escape(kw)}\b")
    for kw in [
        "google chrome",
        "chromium",
        "chrome os",
        "chromeos",
        "google v8",
        "blink",
        "skia",
        "angle",
        "pdfium",
        "mojo",
        "dawn",
        "webgpu",
        "omnibox",
        "fedcm",
        "autofill",
    ]
]

REF_DOMAINS = (
    "chromium.org",
    "googlechromereleases.blogspot.com",
    "crbug.com",
    "chromium.googlesource.com",
)

CVE_RE = re.compile(r"^CVE-\d{4}-\d+\.json$")

BUG_ID_RE = re.compile(
    r"(?:crbug\.com|code\.google\.com/p/chromium/issues/detail\?id=|issues\.chromium\.org/issues/)(\d+)"
)
COMMIT_RE = re.compile(
    r"chromium\.googlesource\.com/(?:chromium/src|[^/]+(?:/[^/]+)?)/\+/([0-9a-f]{40})"
)


def parse_references(references):
    bug_ids = set()
    commit_hashes = set()
    for ref in references:
        url = ref.get("url", "")
        for m in BUG_ID_RE.finditer(url):
            bug_ids.add(m.group(1))
        for m in COMMIT_RE.finditer(url):
            commit_hashes.add(m.group(1))
    return sorted(bug_ids), sorted(commit_hashes)


def is_chromium_cve(cve_dict):
    cna = cve_dict.get("containers", {}).get("cna", {})
    descs = " ".join(d.get("value", "") for d in cna.get("descriptions", [])).lower()
    refs = " ".join(r.get("url", "") for r in cna.get("references", [])).lower()

    for p in PATTERNS:
        if p.search(descs):
            return True
    for domain in REF_DOMAINS:
        if domain in refs:
            return True
    for a in cna.get("affected", []):
        vendor = a.get("vendor", "").lower()
        product = a.get("product", "").lower()
        if "google" in vendor and any(
            p in product for p in ("chrome", "chromium", "v8")
        ):
            return True
    return False


def process_dir(args):
    root, cves, skip_ids = args
    results = []
    for cve in cves:
        cve_id = cve.removesuffix(".json")
        if cve_id in skip_ids:
            continue
        filepath = os.path.join(root, cve)
        with open(filepath) as f:
            cve_dict = json.load(f)
        if not is_chromium_cve(cve_dict):
            continue

        cna = cve_dict["containers"]["cna"]
        meta = cve_dict["cveMetadata"]
        description = " ".join(d["value"] for d in cna.get("descriptions", []))
        affected = cna.get("affected", [])
        vendors = list({a.get("vendor", "") for a in affected})
        products = list({a.get("product", "") for a in affected})
        references = cna.get("references", [])
        urls = [r.get("url", "") for r in references]
        bug_ids, commit_hashes = parse_references(references)

        metadata = {
            "date_published": meta.get("datePublished", ""),
            "state": meta.get("state", ""),
            "vendors": vendors,
            "products": products,
            "references": urls,
        }
        if bug_ids:
            metadata["bug_ids"] = bug_ids
        if commit_hashes:
            metadata["commit_hashes"] = commit_hashes

        results.append(
            {
                "id": cve_id,
                "document": description,
                "metadata": metadata,
            }
        )
    return results


def main():
    print("Collecting CVEs...")
    existing = get_existing_cve_ids()

    tasks = []
    for root, _, filenames in os.walk(config.cves):
        cves = [
            f
            for f in filenames
            if CVE_RE.match(f) and f.removesuffix(".json") not in existing
        ]
        if cves:
            tasks.append((root, cves, existing))

    if not tasks:
        print("Nothing to do")
        return

    written = 0
    batch_ids, batch_docs, batch_metas = [], [], []

    with ProcessPoolExecutor() as pool:
        for batch in pool.map(process_dir, tasks):
            for item in batch:
                batch_ids.append(item["id"])
                batch_docs.append(item["document"])
                batch_metas.append(item["metadata"])
                written += 1

                if len(batch_ids) >= 100:
                    upsert_cves(batch_ids, batch_docs, batch_metas)
                    batch_ids, batch_docs, batch_metas = [], [], []

    if batch_ids:
        upsert_cves(batch_ids, batch_docs, batch_metas)

    print(f"Collected {written} CVEs")


if __name__ == "__main__":
    main()
