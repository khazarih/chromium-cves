import json
import time
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from db import get_cves_collection, get_existing_commit_hashes

GITILES_LOG_URL = "https://chromium.googlesource.com/chromium/src/+log"
GITILES_PREFIX = ")]}'"

NOISE_RE = re.compile(
    r"(^Roll |^Merge |^Automated |^CQ |^Land |^Revert \"Roll|"
    r"^Cherry pick of|^Propagate|^\[Chromium\]|^Update of ^Test:|^Reland)",
    re.IGNORECASE,
)


def query_gitiles(bug_id, retries=2):
    url = f"{GITILES_LOG_URL}?q=bug:{bug_id}&format=JSON"
    for attempt in range(retries):
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 429:
                time.sleep(1 * (attempt + 1))
                continue
            if resp.status_code != 200:
                return []
            text = resp.text
            if text.startswith(GITILES_PREFIX):
                text = text[len(GITILES_PREFIX) :]
            data = json.loads(text)
            results = []
            for e in data.get("log", []):
                h = e.get("commit")
                msg = e.get("message", "")
                if h and not NOISE_RE.match(msg.split("\n")[0]):
                    results.append(h)
            return results[:5]
        except requests.RequestException, ValueError:
            if attempt < retries - 1:
                time.sleep(0.5)
    return []


def resolve_cves():
    col = get_cves_collection()
    results = col.get(include=["metadatas"])
    existing_commits = get_existing_commit_hashes()

    to_resolve = []
    for cve_id, metadata in zip(results["ids"], results["metadatas"]):
        bug_ids = metadata.get("bug_ids") or []
        commit_hashes = metadata.get("commit_hashes") or []
        if not bug_ids:
            continue
        if commit_hashes and all(h in existing_commits for h in commit_hashes):
            continue
        to_resolve.append((cve_id, metadata))

    if not to_resolve:
        print("Nothing to resolve")
        return

    print(f"Resolving {len(to_resolve)} CVEs...")
    resolved = 0

    def resolve_one(args):
        cve_id, metadata = args
        bug_ids = metadata.get("bug_ids") or []
        existing_hashes = set(metadata.get("commit_hashes") or [])
        for bug_id in bug_ids:
            commits = query_gitiles(bug_id)
            for h in commits:
                if h not in existing_hashes:
                    existing_hashes.add(h)
        return cve_id, existing_hashes

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(resolve_one, item): item for item in to_resolve}
        for future in as_completed(futures):
            cve_id, new_hashes = future.result()
            if new_hashes:
                metadata = futures[future][1]
                updated = {**metadata, "commit_hashes": sorted(new_hashes)}
                col.update(ids=[cve_id], metadatas=[updated])
                existing_commits.update(new_hashes)
                resolved += 1
            if resolved % 100 == 0 and resolved > 0:
                print(f"  resolved {resolved}/{len(to_resolve)}...")

    print(f"Resolved {resolved} CVEs with commit hashes")


if __name__ == "__main__":
    resolve_cves()
