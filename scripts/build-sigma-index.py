#!/usr/bin/env python3
"""Build the Sigma rule attribution index (DRL-1.1) from a SigmaHQ checkout.

Usage:
    python3 scripts/build-sigma-index.py <sigma-repo-root> > sigma-index.json
    python3 scripts/build-sigma-index.py <sigma-repo-root> -o lab/state/sigma/index.json

Emits {"<rule title>": {"author": "...", "level": "..."}}. The title is the
rule identifier both chainsaw and Velociraptor curated-Sigma report, and the
join key for cards' detection.expected_sigma. Rules without an author are
emitted with an empty author so the Go loader fails on them explicitly
(fail-closed attribution).

Parses only the flat header fields (title/id/author/level) — no YAML
dependency; sigma rule headers are plain "key: value" lines.
"""

import argparse
import json
import os
import sys

HEADER_FIELDS = ("title", "id", "author", "level")


def parse_rule(path):
    # M4-live fix: the old header-termination logic stopped at the first
    # unknown alphanumeric key ("status:"/"description:" precede "author:" in
    # every SigmaHQ rule) — the live index build produced 3164/3164 rules
    # with an empty author. New approach: scan the whole file for top-level
    # (column-0) "key: value" lines whose key is one of HEADER_FIELDS.
    # title/id/author/level only ever appear at top level; "level:" sits after
    # the detection block in many rules, so no early break is safe. List
    # documents (first line "- ...") are skipped as non-rules.
    meta = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            if line[:1] in (" ", "\t") or line.lstrip().startswith("-"):
                continue  # nested content / list items: never header fields
            st = line.strip()
            key, sep, value = st.partition(":")
            if not sep:
                continue
            key = key.strip()
            if key in HEADER_FIELDS and key not in meta:
                v = value.strip().strip('"').strip("'")
                if v:
                    meta[key] = v
    return meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sigma_root")
    ap.add_argument("-o", "--out", default=None)
    args = ap.parse_args()

    index = {}
    rules_dir = os.path.join(args.sigma_root, "rules")
    if not os.path.isdir(rules_dir):
        print(f"not a sigma checkout: {rules_dir}", file=sys.stderr)
        sys.exit(1)
    for dirpath, _dirnames, filenames in os.walk(rules_dir):
        for name in filenames:
            if not name.endswith(".yml"):
                continue
            meta = parse_rule(os.path.join(dirpath, name))
            title = meta.get("title")
            if not title:
                continue
            index[title] = {
                "author": meta.get("author", ""),
                "level": meta.get("level", ""),
                "id": meta.get("id", ""),
            }

    blob = json.dumps(index, indent=2, sort_keys=True, ensure_ascii=False)
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob + "\n")
    else:
        print(blob)
    missing = [t for t, m in index.items() if not m["author"]]
    if missing:
        print(f"warning: {len(missing)} rules without author (loader will fail on them)", file=sys.stderr)


if __name__ == "__main__":
    main()
