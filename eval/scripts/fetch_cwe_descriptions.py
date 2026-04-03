#!/usr/bin/env python3
"""Fetch CWE descriptions from MITRE's official CWE list and build wrong-CWE mapping."""

import json
import os
import time
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET

# All 44 CWEs in our dataset
CWES = [
    "CWE-770", "CWE-119", "CWE-125", "CWE-77", "CWE-88", "CWE-79",
    "CWE-613", "CWE-787", "CWE-476", "CWE-416", "CWE-287", "CWE-20",
    "CWE-190", "CWE-362", "CWE-22", "CWE-264", "CWE-369", "CWE-254",
    "CWE-400", "CWE-835", "CWE-347", "CWE-200", "CWE-682", "CWE-269",
    "CWE-665", "CWE-122", "CWE-59", "CWE-399", "CWE-94", "CWE-189",
    "CWE-191", "CWE-772", "CWE-863", "CWE-755", "CWE-415", "CWE-670",
    "CWE-674", "CWE-310", "CWE-924", "CWE-327", "CWE-134", "CWE-120",
    "CWE-346", "CWE-255",
]

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "configs", "cwe_descriptions.json")
MAPPING_PATH = os.path.join(os.path.dirname(__file__), "..", "configs", "cwe_wrong_mapping.json")


def fetch_cwe_description(cwe_id):
    """Fetch CWE name and description from MITRE website."""
    num = cwe_id.split("-")[1]
    url = f"https://cwe.mitre.org/data/definitions/{num}.html"
    req = urllib.request.Request(url, headers={"User-Agent": "siftrank-eval/1.0"})

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")

        # Extract title (contains CWE name)
        import re
        title_match = re.search(r"<title>(.*?)</title>", html, re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            # Title format: "CWE - CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer (4.17)"
            name_match = re.search(r"CWE-\d+:\s*(.+?)(?:\s*\(\d)", title)
            if name_match:
                name = name_match.group(1).strip()
            else:
                name = title
        else:
            name = cwe_id

        # Extract description from the "Description" div
        desc_match = re.search(
            r'<div class="indent">\s*(?:<div[^>]*>)?\s*(.*?)\s*(?:</div>\s*)?</div>',
            html,
            re.DOTALL,
        )
        if desc_match:
            desc = re.sub(r"<[^>]+>", "", desc_match.group(1)).strip()
            # Clean up whitespace
            desc = " ".join(desc.split())
        else:
            desc = ""

        return name, desc

    except Exception as e:
        print(f"  Error fetching {cwe_id}: {e}")
        return cwe_id, ""


# Categorize CWEs by type for building wrong mappings
# These categories are based on CWE's own pillar/class hierarchy
CWE_CATEGORIES = {
    "memory": ["CWE-119", "CWE-125", "CWE-787", "CWE-416", "CWE-122", "CWE-120", "CWE-415", "CWE-190", "CWE-191", "CWE-189"],
    "injection": ["CWE-77", "CWE-88", "CWE-79", "CWE-94", "CWE-134"],
    "auth_access": ["CWE-287", "CWE-264", "CWE-269", "CWE-863", "CWE-255", "CWE-613"],
    "input_validation": ["CWE-20", "CWE-22", "CWE-59", "CWE-346", "CWE-347"],
    "resource": ["CWE-770", "CWE-400", "CWE-772", "CWE-399", "CWE-835", "CWE-674"],
    "crypto": ["CWE-310", "CWE-327", "CWE-924"],
    "logic": ["CWE-362", "CWE-369", "CWE-682", "CWE-665", "CWE-670", "CWE-755", "CWE-200", "CWE-254", "CWE-476"],
}


def build_wrong_mapping(cwe_list):
    """Build a static mapping from each CWE to an unrelated CWE.

    Rules:
    - The wrong CWE must be from a DIFFERENT category
    - The mapping is deterministic and static (same CWE always maps to same wrong CWE)
    - Each CWE in the dataset gets a mapping
    """
    # Build reverse lookup: CWE -> category
    cwe_to_cat = {}
    for cat, cwes in CWE_CATEGORIES.items():
        for cwe in cwes:
            cwe_to_cat[cwe] = cat

    # Sort categories for deterministic assignment
    cat_list = sorted(CWE_CATEGORIES.keys())

    mapping = {}
    for cwe in sorted(cwe_list):
        my_cat = cwe_to_cat.get(cwe, "unknown")

        # Pick from a different category, cycling through categories
        # Use a deterministic offset based on CWE number
        num = int(cwe.split("-")[1])
        candidates = []
        for cat in cat_list:
            if cat != my_cat:
                candidates.extend(CWE_CATEGORIES[cat])

        # Pick deterministically
        wrong_cwe = candidates[num % len(candidates)]

        # Make sure we don't map to ourselves (shouldn't happen since different category)
        if wrong_cwe == cwe:
            wrong_cwe = candidates[(num + 1) % len(candidates)]

        mapping[cwe] = wrong_cwe

    return mapping


def main():
    os.makedirs(os.path.dirname(os.path.abspath(OUTPUT_PATH)), exist_ok=True)

    # Load existing if resuming
    descriptions = {}
    if os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH) as f:
            descriptions = json.load(f)

    remaining = [c for c in CWES if c not in descriptions]
    print(f"Fetching {len(remaining)} CWE descriptions ({len(descriptions)} cached)")

    for i, cwe_id in enumerate(remaining):
        print(f"[{i+1}/{len(remaining)}] {cwe_id}...", end=" ", flush=True)
        name, desc = fetch_cwe_description(cwe_id)
        print(f"-> {name[:60]}")
        descriptions[cwe_id] = {"name": name, "description": desc}

        with open(OUTPUT_PATH, "w") as f:
            json.dump(descriptions, f, indent=2, sort_keys=True)

        if i < len(remaining) - 1:
            time.sleep(1)  # Be polite to MITRE

    print(f"\nDescriptions saved to {OUTPUT_PATH}")

    # Build and save wrong-CWE mapping
    wrong_mapping = build_wrong_mapping(CWES)
    with open(MAPPING_PATH, "w") as f:
        json.dump(wrong_mapping, f, indent=2, sort_keys=True)

    print(f"Wrong-CWE mapping saved to {MAPPING_PATH}")

    # Verify no self-mappings and all cross-category
    cwe_to_cat = {}
    for cat, cwes in CWE_CATEGORIES.items():
        for cwe in cwes:
            cwe_to_cat[cwe] = cat

    print("\nWrong-CWE mapping verification:")
    for cwe, wrong in sorted(wrong_mapping.items()):
        my_cat = cwe_to_cat.get(cwe, "?")
        wrong_cat = cwe_to_cat.get(wrong, "?")
        ok = "OK" if my_cat != wrong_cat else "SAME-CAT!"
        desc_name = descriptions.get(cwe, {}).get("name", "?")[:30]
        wrong_name = descriptions.get(wrong, {}).get("name", "?")[:30]
        print(f"  {cwe} ({my_cat[:8]:8s} {desc_name:30s}) -> {wrong} ({wrong_cat[:8]:8s} {wrong_name}) [{ok}]")


if __name__ == "__main__":
    main()
