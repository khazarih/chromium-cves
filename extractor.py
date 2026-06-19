import base64
import re
import time
import requests
from concurrent.futures import ThreadPoolExecutor
from db import get_cves_collection, get_patches_collection, get_existing_commit_hashes

GITILES_DIFF_URL = (
    "https://chromium.googlesource.com/chromium/src/+diff/{commit}%5E%21/?format=TEXT"
)
GITILES_PREFIX = ")]}'"
RATE_LIMIT_DELAY = 0.3

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

        added_lines = []
        for hunk in file_info["hunks"]:
            for line in hunk["lines"]:
                if line.startswith("+") and not line.startswith("+++"):
                    added_lines.append(line[1:])

        if not added_lines:
            continue

        code = "\n".join(added_lines)
        patches.append(
            {
                "file_path": path,
                "language": ext.lstrip("."),
                "code": code,
            }
        )

    return patches


def extract_from_commits():
    cves_col = get_cves_collection()
    patches_col = get_patches_collection()
    results = cves_col.get(include=["metadatas"])

    existing_commits = get_existing_commit_hashes()

    to_extract = []
    for cve_id, metadata in zip(results["ids"], results["metadatas"]):
        commit_hashes = metadata.get("commit_hashes") or []
        if not commit_hashes:
            continue
        pending = [h for h in commit_hashes if h not in existing_commits]
        if not pending:
            continue
        to_extract.append((cve_id, metadata, pending))

    if not to_extract:
        print("Nothing to extract")
        return

    print(f"Extracting patches from {len(to_extract)} CVEs...")
    extracted = 0

    def process_commit(args):
        cve_id, commit_hash = args
        diff_text = fetch_diff(commit_hash)
        if not diff_text:
            return []
        files = parse_diff(diff_text)
        patches = extract_patched_code(files)
        results = []
        for patch in patches:
            patch_id = f"{cve_id}::{commit_hash[:12]}::{patch['file_path']}"
            results.append(
                {
                    "id": patch_id,
                    "code": patch["code"],
                    "metadata": {
                        "cve_id": cve_id,
                        "commit_hash": commit_hash,
                        "file_path": patch["file_path"],
                        "language": patch["language"],
                    },
                }
            )
        return results

    tasks = []
    for cve_id, _, hashes in to_extract:
        for h in hashes[:5]:
            tasks.append((cve_id, h))

    batch_ids, batch_docs, batch_metas = [], [], []
    seen_ids = set()
    done = 0

    with ThreadPoolExecutor(max_workers=20) as pool:
        for results in pool.map(process_commit, tasks):
            done += 1
            if done % 50 == 0:
                print(
                    f"  {done}/{len(tasks)} commits processed, {extracted} patches..."
                )
            for item in results:
                if item["id"] in seen_ids:
                    continue
                seen_ids.add(item["id"])
                batch_ids.append(item["id"])
                batch_docs.append(item["code"])
                batch_metas.append(item["metadata"])
                extracted += 1

                if len(batch_ids) >= 50:
                    patches_col.upsert(
                        ids=batch_ids,
                        documents=batch_docs,
                        metadatas=batch_metas,
                    )
                    batch_ids, batch_docs, batch_metas = [], [], []
            time.sleep(RATE_LIMIT_DELAY)

    if batch_ids:
        patches_col.upsert(
            ids=batch_ids,
            documents=batch_docs,
            metadatas=batch_metas,
        )

    print(f"Extracted {extracted} patches")


if __name__ == "__main__":
    extract_from_commits()
