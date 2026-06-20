import json
import time
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from db import get_cves_collection

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

    to_resolve = []
    already_done = 0
    for cve_id, metadata in zip(results["ids"], results["metadatas"]):
        bug_ids = metadata.get("bug_ids") or []
        commit_hashes = metadata.get("commit_hashes") or []
        if not bug_ids:
            continue
        if commit_hashes:
            already_done += 1
            continue
        to_resolve.append((cve_id, metadata))

    if not to_resolve:
        print(
            f"Nothing to resolve — all {already_done} CVEs with bugs already resolved"
        )
        return

    print(f"Resolving {len(to_resolve)} CVEs ({already_done} already done)...")

    resolved = 0
    errors = 0
    start = time.time()

    def resolve_one(args):
        cve_id, metadata = args
        bug_ids = metadata.get("bug_ids") or []
        new_hashes = set()
        for bug_id in bug_ids:
            commits = query_gitiles(bug_id)
            for h in commits:
                new_hashes.add(h)
        return cve_id, new_hashes

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(resolve_one, item): item for item in to_resolve}
        for future in as_completed(futures):
            try:
                cve_id, new_hashes = future.result()
            except Exception:
                errors += 1
                continue

            if new_hashes:
                metadata = futures[future][1]
                existing = set(metadata.get("commit_hashes") or [])
                updated = {**metadata, "commit_hashes": sorted(existing | new_hashes)}
                col.update(ids=[cve_id], metadatas=[updated])
                resolved += 1

            done = resolved + errors
            if done % 50 == 0 or done == len(to_resolve):
                elapsed = time.time() - start
                rate = done / elapsed if elapsed > 0 else 0
                eta = (len(to_resolve) - done) / rate if rate > 0 else 0
                print(
                    f"  {done}/{len(to_resolve)} "
                    f"({resolved} resolved, {errors} errors) "
                    f"[{rate:.1f}/s, ETA {eta:.0f}s]",
                    end="\r",
                )

    print(f"\nResolved {resolved} CVEs ({errors} errors)")


if __name__ == "__main__":
    resolve_cves()
