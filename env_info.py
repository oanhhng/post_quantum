"""Print the experiment environment (paste it into the lab notebook for reproducibility)."""
import json
import os
import platform
import subprocess
import sys
from importlib import metadata


def _ver(pkg: str) -> str:
    try:
        return metadata.version(pkg)
    except metadata.PackageNotFoundError:
        return "not installed"


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "n/a"


def collect() -> dict:
    return {
        "os": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "python": sys.version.split()[0],
        "kyber-py": _ver("kyber-py"),
        "cryptography": _ver("cryptography"),
        "liboqs-python": _ver("liboqs-python"),
        "openssl_cli": _run(["openssl", "version"]),
        "tshark": (_run(["tshark", "--version"]).splitlines() or ["n/a"])[0],
    }


if __name__ == "__main__":
    info = collect()
    print(json.dumps(info, indent=2, ensure_ascii=False))
    print("\nAlso record manually: RAM, physical machine vs VM/WSL, power mode, background processes.")
