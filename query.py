import json
import argparse
from db import query_cves, query_patches, get_cve_metadata


def search_cves(query, n=5):
    results = query_cves(query, n_results=n)
    if not results["ids"][0]:
        print("No results")
        return
    for cve_id, doc, meta, dist in zip(
        results["ids"][0],
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        score = 1 - dist
        severity = meta.get("severity", "n/a")
        problem_types = meta.get("problem_types", [])
        pt_str = " | ".join(problem_types) if problem_types else "n/a"

        print(f"\n{'=' * 60}")
        print(f"  {cve_id} | {pt_str} | {severity}  (score: {score:.3f})")
        print(f"  Published: {meta.get('date_published', 'n/a')}")
        print(f"  Products:  {', '.join(meta.get('products', []))}")
        print(f"  Bug IDs:   {', '.join(meta.get('bug_ids', []))}")
        print(f"  Commits:   {', '.join(meta.get('commit_hashes', [])[:3])}")
        print(f"\n  {doc[:200]}{'...' if len(doc) > 200 else ''}")


def search_patches(query, n=5, language=None, full=False):
    where = {"language": language} if language else None
    results = query_patches(query, n_results=n, where=where)
    if not results["ids"][0]:
        print("No results")
        return
    for patch_id, doc, meta, dist in zip(
        results["ids"][0],
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        score = 1 - dist
        severity = meta.get("severity", "n/a")
        problem_types = meta.get("problem_types", [])
        pt_str = " | ".join(problem_types) if problem_types else "n/a"

        print(f"\n{'=' * 60}")
        print(f"  {meta.get('cve_id', 'n/a')} | {pt_str} | {severity}")
        print(f"  {meta.get('file_path', 'n/a')}  ({meta.get('language', 'n/a')})")
        print(f"  Score: {score:.3f}  Commit: {meta.get('commit_hash', 'n/a')[:12]}")

        cve_desc = meta.get("cve_description", "")
        if cve_desc:
            print("\n  CVE Description:")
            print(
                f"  {cve_desc if full else cve_desc[:200] + ('...' if len(cve_desc) > 200 else '')}"
            )

        commit_msg = meta.get("commit_message", "")
        if commit_msg:
            msg_preview = commit_msg.split("\n")[:3]
            print("\n  Commit Message:")
            for line in msg_preview:
                print(f"  {line}")

        vuln = meta.get("vulnerable_code", "")
        patched = meta.get("patched_code", "")
        if vuln:
            print("\n--- Vulnerable code (before):")
            print(vuln if full else vuln[:300] + ("..." if len(vuln) > 300 else ""))
        if patched:
            print("\n+++ Patched code (after):")
            print(
                patched
                if full
                else patched[:300] + ("..." if len(patched) > 300 else "")
            )


def show_cve(cve_id):
    result = get_cve_metadata(cve_id)
    if not result:
        print(f"CVE not found: {cve_id}")
        return
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Chromium CVE search")
    sub = parser.add_subparsers(dest="command")

    p_cve = sub.add_parser("cves", help="Search CVE descriptions")
    p_cve.add_argument("query", help="Search query")
    p_cve.add_argument("-n", type=int, default=5)

    p_patch = sub.add_parser("patches", help="Search patched code")
    p_patch.add_argument("query", help="Search query")
    p_patch.add_argument("-n", type=int, default=5)
    p_patch.add_argument("--lang", help="Filter by language")
    p_patch.add_argument(
        "--full", action="store_true", help="Show full code without truncation"
    )

    p_show = sub.add_parser("show", help="Show CVE details")
    p_show.add_argument("cve_id", help="CVE ID (e.g. CVE-2022-3075)")

    args = parser.parse_args()
    if args.command == "cves":
        search_cves(args.query, args.n)
    elif args.command == "patches":
        search_patches(args.query, args.n, args.lang, args.full)
    elif args.command == "show":
        show_cve(args.cve_id)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
