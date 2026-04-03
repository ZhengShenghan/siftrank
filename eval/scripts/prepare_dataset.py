#!/usr/bin/env python3
"""
Extract evaluation pairs from the pickle dataset into JSON for the Go eval tool.

For each vulnerable function (label=1) in a CVE binary (d0), finds the matching
function in the patched binary (d1) to create a positive/negative pair.

Output: JSON array of objects, each with:
  - func: function name
  - addr: not available in this dataset, uses binary path instead
  - cve: CVE ID extracted from path
  - binary: binary name from path
  - decompiled: decompiled pseudocode
  - vulnerable: true/false ground truth
  - source: "cve" or "patched" indicating which binary it came from
"""

import json
import os
import pickle
import re
import sys


def extract_cve(path):
    """Extract CVE ID from binary path."""
    m = re.search(r"(CVE-\d{4}-\d+)", path)
    return m.group(1) if m else "unknown"


def extract_binary_name(path):
    """Extract binary name from path."""
    return os.path.basename(path)


def main():
    if len(sys.argv) < 2:
        print("Usage: prepare_dataset.py <pickle_file> [output_json]")
        sys.exit(1)

    pickle_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "eval/data/eval_pairs.json"

    # Load CVE->CWE mapping if available
    cwe_map_path = os.path.join(os.path.dirname(__file__), "..", "configs", "cve_cwe_map.json")
    cwe_map = {}
    if os.path.exists(cwe_map_path):
        with open(cwe_map_path) as f:
            cwe_map = json.load(f)
        print(f"Loaded CVE->CWE mapping with {len(cwe_map)} entries")

    print(f"Loading pickle from {pickle_path}...")
    with open(pickle_path, "rb") as f:
        data = pickle.load(f)

    print(f"Loaded {len(data)} binary pairs")

    eval_samples = []
    skipped = 0

    for pair_idx, (d0, d1) in enumerate(data):
        cve = extract_cve(d0["path"])
        binary = extract_binary_name(d0["path"])
        d1_funcs = d1["funcs"]

        # Get CWE info if available
        cwe_ids = []
        if cve in cwe_map:
            cwe_ids = cwe_map[cve].get("cwe_ids", [])

        for func_name, func_data in d0["funcs"].items():
            if func_data["label"] != 1:
                continue

            # Positive sample: vulnerable function from CVE binary
            decompiled = func_data.get("decompiled", "")
            if not decompiled:
                skipped += 1
                continue

            eval_samples.append({
                "func": func_name,
                "binary": binary,
                "cve": cve,
                "cwe_ids": cwe_ids,
                "decompiled": decompiled,
                "vulnerable": True,
                "source": "cve",
                "pair_idx": pair_idx,
            })

            # Negative sample: same function from patched binary
            if func_name in d1_funcs:
                patched_decompiled = d1_funcs[func_name].get("decompiled", "")
                if not patched_decompiled:
                    skipped += 1
                    continue

                eval_samples.append({
                    "func": func_name,
                    "binary": extract_binary_name(d1["path"]),
                    "cve": cve,
                    "cwe_ids": cwe_ids,
                    "decompiled": patched_decompiled,
                    "vulnerable": False,
                    "source": "patched",
                    "pair_idx": pair_idx,
                })

    # Stats
    positives = sum(1 for s in eval_samples if s["vulnerable"])
    negatives = sum(1 for s in eval_samples if not s["vulnerable"])
    unique_cves = len(set(s["cve"] for s in eval_samples))
    with_cwe = sum(1 for s in eval_samples if s["cwe_ids"])

    print(f"\nDataset stats:")
    print(f"  Total samples:  {len(eval_samples)}")
    print(f"  Positive (vuln): {positives}")
    print(f"  Negative (safe): {negatives}")
    print(f"  Skipped (no decompiled): {skipped}")
    print(f"  Unique CVEs:    {unique_cves}")
    print(f"  Samples with CWE mapping: {with_cwe}")

    # Write output
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(eval_samples, f, indent=2)

    print(f"\nWritten to {output_path}")
    print(f"File size: {os.path.getsize(output_path) / 1024 / 1024:.1f} MB")


if __name__ == "__main__":
    main()
