"""Download the NIST ACVP vectors for ML-KEM (FIPS 203) and write a manifest (source, date, sha256).

Run from the project root:  python -m tests.vectors.fetch_vectors
The manifest (tests/vectors/MANIFEST.json) is the provenance evidence to cite in the report.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"
SETS = {"keygen": "ML-KEM-keyGen-FIPS203", "encapdecap": "ML-KEM-encapDecap-FIPS203"}
FILES = ("prompt.json", "expectedResults.json")
ROOT = Path(__file__).parent


def main() -> None:
    manifest = {"downloaded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "files": []}
    for folder, remote in SETS.items():
        (ROOT / folder).mkdir(exist_ok=True)
        for name in FILES:
            url = f"{BASE}/{remote}/{name}"
            data = urllib.request.urlopen(url, timeout=60).read()
            (ROOT / folder / name).write_bytes(data)
            manifest["files"].append({"path": f"{folder}/{name}", "url": url,
                                      "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            print("OK", url, len(data), "B")
    (ROOT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("-> MANIFEST.json (also note the ACVP-Server commit if you need exact traceability)")


if __name__ == "__main__":
    main()
