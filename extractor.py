import base64
import re
import time
import requests
from concurrent.futures import ThreadPoolExecutor
from db import get_cves_collection, get_patches_collection

GITILES_DIFF_URL = (
    "https://chromium.googlesource.com/chromium/src/+diff/{commit}%5E%21/?format=TEXT"
)

SOURCE_EXTS = {
    ".cc",
    ".cpp",
    ".c",
    ".h",
    ".hpp",
    ".js",
    ".ts",
    ".py",
    ".java",
    ".rs",
    ".go",
    ".swift",
    ".mm",
    ".m",
}


def fetch_diff(commit_hash):
    url = GITILES_DIFF_URL.format(commit=commit_hash)
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code != 200:
            return None
        return base64.b64decode(resp.text).decode("utf-8", errors="replace")
    except requests.RequestException:
        return None


def parse_diff(diff_text):
    files = []
    current_file = None
    hunks = []

    for line in diff_text.split("\n"):
        if line.startswith("diff --git"):
            if current_file and hunks:
                files.append({"path": current_file, "hunks": hunks})
            match = re.search(r"b/(.+)$", line)
            current_file = match.group(1) if match else None
            hunks = []
        elif line.startswith("@@"):
            hunks.append({"header": line, "lines": []})
        elif hunks:
            hunks[-1]["lines"].append(line)

    if current_file and hunks:
        files.append({"path": current_file, "hunks": hunks})

    return files


def extract_patched_code(files):
    patches = []
    for file_info in files:
        path = file_info["path"]
        ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
        if ext not in SOURCE_EXTS:
            continue

        removed_lines = []
        added_lines = []
        for hunk in file_info["hunks"]:
            for line in hunk["lines"]:
                if line.startswith("-") and not line.startswith("---"):
                    removed_lines.append(line[1:])
                elif line.startswith("+") and not line.startswith("+++"):
                    added_lines.append(line[1:])

        if not added_lines:
            continue

        patches.append(
            {
                "file_path": path,
                "language": ext.lstrip("."),
                "vulnerable_code": "\n".join(removed_lines),
                "patched_code": "\n".join(added_lines),
            }
        )

    return patches


def extract_from_commits():
    cves_col = get_cves_collection()
    patches_col = get_patches_collection()
    results = cves_col.get(include=["metadatas"])

    existing_patch_ids = set(patches_col.get(include=[])["ids"] or [])

    to_extract = []
    for cve_id, metadata in zip(results["ids"], results["metadatas"]):
        commit_hashes = metadata.get("commit_hashes") or []
        if not commit_hashes:
            continue
        pending = []
        for h in commit_hashes:
            prefix = f"{cve_id}::{h[:12]}"
            if not any(pid.startswith(prefix) for pid in existing_patch_ids):
                pending.append(h)
        if not pending:
            continue
        to_extract.append((cve_id, pending))

    if not to_extract:
        print("Nothing to extract — all patches already collected")
        return

    tasks = []
    for cve_id, hashes in to_extract:
        for h in hashes[:5]:
            tasks.append((cve_id, h))

    print(f"Extracting patches: {len(to_extract)} CVEs, {len(tasks)} commits")

    extracted = 0
    skipped = 0
    start = time.time()

    def process_commit(args):
        cve_id, commit_hash = args
        diff_text = fetch_diff(commit_hash)
        if not diff_text:
            return []
        files = parse_diff(diff_text)
        patches = extract_patched_code(files)
        return [
            {
                "id": f"{cve_id}::{commit_hash[:12]}::{p['file_path']}",
                "document": f"// Vulnerable code:\n{p['vulnerable_code']}\n\n// Patched code:\n{p['patched_code']}",
                "metadata": {
                    "cve_id": cve_id,
                    "commit_hash": commit_hash,
                    "file_path": p["file_path"],
                    "language": p["language"],
                    "vulnerable_code": p["vulnerable_code"],
                    "patched_code": p["patched_code"],
                },
            }
            for p in patches
        ]

    batch_ids, batch_docs, batch_metas = [], [], []

    with ThreadPoolExecutor(max_workers=20) as pool:
        for results in pool.map(process_commit, tasks):
            if not results:
                skipped += 1
            for item in results:
                if item["id"] in existing_patch_ids:
                    skipped += 1
                    continue
                existing_patch_ids.add(item["id"])
                batch_ids.append(item["id"])
                batch_docs.append(item["document"])
                batch_metas.append(item["metadata"])
                extracted += 1

                if len(batch_ids) >= 50:
                    patches_col.upsert(
                        ids=batch_ids,
                        documents=batch_docs,
                        metadatas=batch_metas,
                    )
                    batch_ids, batch_docs, batch_metas = [], [], []

            done = extracted + skipped
            if done % 25 == 0 or done == len(tasks):
                elapsed = time.time() - start
                rate = done / elapsed if elapsed > 0 else 0
                eta = (len(tasks) - done) / rate if rate > 0 else 0
                print(
                    f"  {done}/{len(tasks)} commits "
                    f"({extracted} patches, {skipped} skipped) "
                    f"[{rate:.1f}/s, ETA {eta:.0f}s]",
                    end="\r",
                )

    if batch_ids:
        patches_col.upsert(
            ids=batch_ids,
            documents=batch_docs,
            metadatas=batch_metas,
        )

    print(f"\nExtracted {extracted} patches ({skipped} skipped)")


if __name__ == "__main__":
    extract_from_commits()
