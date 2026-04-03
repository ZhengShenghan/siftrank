#!/usr/bin/env python3
"""Fetch CVE-to-CWE mappings from NVD API for all CVEs in the dataset."""

import json
import time
import urllib.request
import urllib.error
import sys
import os

CVES = [
    "CVE-2003-0577", "CVE-2004-0991", "CVE-2006-1655", "CVE-2010-0743",
    "CVE-2010-2947", "CVE-2010-4352", "CVE-2011-4620", "CVE-2011-5326",
    "CVE-2012-0046", "CVE-2012-1581", "CVE-2012-1582", "CVE-2012-2737",
    "CVE-2012-2738", "CVE-2012-2812", "CVE-2012-2813", "CVE-2012-2814",
    "CVE-2012-2836", "CVE-2012-2837", "CVE-2012-2840", "CVE-2012-2841",
    "CVE-2012-2845", "CVE-2012-3505", "CVE-2012-4552", "CVE-2013-4420",
    "CVE-2013-4509", "CVE-2013-6629", "CVE-2013-6630", "CVE-2014-0459",
    "CVE-2014-2525", "CVE-2014-2892", "CVE-2014-3710", "CVE-2014-4607",
    "CVE-2014-6051", "CVE-2014-6052", "CVE-2014-6055", "CVE-2014-8146",
    "CVE-2014-8321", "CVE-2014-8322", "CVE-2014-8323", "CVE-2014-8324",
    "CVE-2014-8517", "CVE-2014-9092", "CVE-2014-9130", "CVE-2014-9645",
    "CVE-2015-1192", "CVE-2015-1197", "CVE-2015-1283", "CVE-2015-1419",
    "CVE-2015-2331", "CVE-2015-2806", "CVE-2015-3202", "CVE-2015-4645",
    "CVE-2015-4760", "CVE-2015-5602", "CVE-2015-6053", "CVE-2015-8080",
    "CVE-2015-8708", "CVE-2015-9059", "CVE-2016-0494", "CVE-2016-0718",
    "CVE-2016-10151", "CVE-2016-10152", "CVE-2016-10324", "CVE-2016-10325",
    "CVE-2016-10326", "CVE-2016-1243", "CVE-2016-2037", "CVE-2016-2312",
    "CVE-2016-2399", "CVE-2016-3178", "CVE-2016-3179", "CVE-2016-3616",
    "CVE-2016-3822", "CVE-2016-3993", "CVE-2016-3994", "CVE-2016-4024",
    "CVE-2016-4330", "CVE-2016-4331", "CVE-2016-4332", "CVE-2016-4333",
    "CVE-2016-4429", "CVE-2016-5735", "CVE-2016-6129", "CVE-2016-6265",
    "CVE-2016-6271", "CVE-2016-8659", "CVE-2016-8674", "CVE-2016-8679",
    "CVE-2016-8680", "CVE-2016-8682", "CVE-2016-8683", "CVE-2016-8684",
    "CVE-2016-9011", "CVE-2016-9063", "CVE-2016-9572", "CVE-2016-9577",
    "CVE-2016-9830", "CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9928",
    "CVE-2017-1000229", "CVE-2017-1000368", "CVE-2017-1000381",
    "CVE-2017-10989", "CVE-2017-11102", "CVE-2017-11114", "CVE-2017-11140",
    "CVE-2017-11332", "CVE-2017-11358", "CVE-2017-11359", "CVE-2017-11541",
    "CVE-2017-11542", "CVE-2017-11636", "CVE-2017-11637", "CVE-2017-11638",
    "CVE-2017-11641", "CVE-2017-11643", "CVE-2017-11722", "CVE-2017-12122",
    "CVE-2017-12951", "CVE-2017-13685", "CVE-2017-13756", "CVE-2017-13760",
    "CVE-2017-14120", "CVE-2017-14121", "CVE-2017-14122", "CVE-2017-14440",
    "CVE-2017-14441", "CVE-2017-14442", "CVE-2017-14448", "CVE-2017-14450",
    "CVE-2017-14632", "CVE-2017-14633", "CVE-2017-15135", "CVE-2017-15286",
    "CVE-2017-15371", "CVE-2017-15372", "CVE-2017-15642", "CVE-2017-15922",
    "CVE-2017-16938", "CVE-2017-17054", "CVE-2017-17440", "CVE-2017-17480",
    "CVE-2017-17554", "CVE-2017-17555", "CVE-2017-2619", "CVE-2017-2887",
    "CVE-2017-3144", "CVE-2017-5226", "CVE-2017-5461", "CVE-2017-5462",
    "CVE-2017-5604", "CVE-2017-5852", "CVE-2017-5896", "CVE-2017-5974",
    "CVE-2017-5975", "CVE-2017-5976", "CVE-2017-5979", "CVE-2017-5981",
    "CVE-2017-6194", "CVE-2017-6307", "CVE-2017-6308", "CVE-2017-6386",
    "CVE-2017-6387", "CVE-2017-6414", "CVE-2017-6448", "CVE-2017-7494",
    "CVE-2017-7502", "CVE-2017-7608", "CVE-2017-7609", "CVE-2017-7610",
    "CVE-2017-7611", "CVE-2017-7613", "CVE-2017-7742", "CVE-2017-7853",
    "CVE-2017-7875", "CVE-2017-7946", "CVE-2017-7994", "CVE-2017-8314",
    "CVE-2017-8362", "CVE-2017-8363", "CVE-2017-8364", "CVE-2017-8779",
    "CVE-2017-9022", "CVE-2017-9058", "CVE-2017-9122", "CVE-2017-9998",
    "CVE-2018-0492", "CVE-2018-10958", "CVE-2018-10998", "CVE-2018-13005",
    "CVE-2018-13441", "CVE-2018-14348", "CVE-2018-14423", "CVE-2018-14522",
    "CVE-2018-14523", "CVE-2018-14526", "CVE-2018-15126", "CVE-2018-15127",
    "CVE-2018-15599", "CVE-2018-16430", "CVE-2018-16435", "CVE-2018-17825",
    "CVE-2018-18088", "CVE-2018-18245", "CVE-2018-20019", "CVE-2018-20021",
    "CVE-2018-20022", "CVE-2018-20023", "CVE-2018-20196", "CVE-2018-20430",
    "CVE-2018-20431", "CVE-2018-20544", "CVE-2018-20685", "CVE-2018-20748",
    "CVE-2018-20749", "CVE-2018-20750", "CVE-2018-20760", "CVE-2018-20761",
    "CVE-2018-20763", "CVE-2018-5146", "CVE-2018-5732", "CVE-2018-5733",
    "CVE-2018-5785", "CVE-2018-6307", "CVE-2018-6544", "CVE-2018-6616",
    "CVE-2018-7752", "CVE-2018-7998", "CVE-2018-8740", "CVE-2019-12295",
    "CVE-2019-15531", "CVE-2019-20387", "CVE-2019-3855", "CVE-2019-3856",
    "CVE-2019-3857", "CVE-2019-3858", "CVE-2019-3859", "CVE-2019-3860",
    "CVE-2019-3861", "CVE-2019-3862", "CVE-2019-6706", "CVE-2019-6956",
    "CVE-2019-8356", "CVE-2019-8357", "CVE-2019-8936", "CVE-2019-9511",
    "CVE-2019-9513", "CVE-2019-9516", "CVE-2020-13977", "CVE-2020-24370",
    "CVE-2020-36277", "CVE-2021-29376", "CVE-2021-30498", "CVE-2022-24884",
    "CVE-2022-30698", "CVE-2022-3204", "CVE-2022-37703", "CVE-2022-37704",
    "CVE-2022-37705", "CVE-2022-38266", "CVE-2023-1999", "CVE-2023-22809",
    "CVE-2023-30577", "CVE-2023-37464", "CVE-2023-45853", "CVE-2023-4863",
    "CVE-2023-50387", "CVE-2024-5564",
]

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "configs", "cve_cwe_map.json")

def fetch_cve(cve_id):
    """Fetch CVE data from NVD API."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    req = urllib.request.Request(url, headers={"User-Agent": "siftrank-eval/1.0"})

    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            if isinstance(e, urllib.error.HTTPError) and e.code in (403, 429):
                wait = 30 * (attempt + 1)
                print(f"  Rate limited ({e.code}), waiting {wait}s...")
                time.sleep(wait)
            else:
                print(f"  Error: {e}, retrying in 10s...")
                time.sleep(10)
    return None


def extract_cwes(nvd_data):
    """Extract CWE IDs from NVD response."""
    cwe_ids = []
    try:
        vulns = nvd_data.get("vulnerabilities", [])
        if not vulns:
            return cwe_ids
        weaknesses = vulns[0].get("cve", {}).get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-") and val != "CWE-Other":
                    cwe_ids.append(val)
    except (KeyError, IndexError):
        pass
    return cwe_ids


def main():
    # Load existing progress if any
    output_path = os.path.abspath(OUTPUT_PATH)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    mapping = {}
    if os.path.exists(output_path):
        with open(output_path) as f:
            mapping = json.load(f)
        print(f"Loaded {len(mapping)} existing entries")

    remaining = [c for c in CVES if c not in mapping]
    print(f"Total CVEs: {len(CVES)}, remaining: {len(remaining)}")

    for i, cve_id in enumerate(remaining):
        print(f"[{i+1}/{len(remaining)}] Fetching {cve_id}...", end=" ", flush=True)

        data = fetch_cve(cve_id)
        if data is None:
            print("FAILED")
            mapping[cve_id] = {"cwe_ids": [], "cwe_names": []}
        else:
            cwes = extract_cwes(data)
            print(f"-> {cwes if cwes else 'no CWE'}")
            mapping[cve_id] = {"cwe_ids": cwes, "cwe_names": []}

        # Save progress after each fetch
        with open(output_path, "w") as f:
            json.dump(mapping, f, indent=2, sort_keys=True)

        # Rate limit: ~5 req / 30s without API key
        if i < len(remaining) - 1:
            time.sleep(6.5)

    # Summary
    with_cwe = sum(1 for v in mapping.values() if v["cwe_ids"])
    without_cwe = sum(1 for v in mapping.values() if not v["cwe_ids"])
    all_cwes = set()
    for v in mapping.values():
        all_cwes.update(v["cwe_ids"])

    print(f"\nDone! {with_cwe} with CWE, {without_cwe} without CWE")
    print(f"Unique CWE IDs: {len(all_cwes)}")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    main()
