#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path


def main():
    p = Path(__file__).parent.parent / "python"
    cmd = ["uv", "run", "pytest", "-q", "--timeout=60", "tests/test_vectors.py", "tests/interface/meshtastic", "tests/interface/test_meshtastic_address.py", "tests/interface/test_meshtastic_translate.py", "tests/interface/meshtastic/test_zephyr_unsupported_portnums.py", "tests/client/test_lci.py", "--tb=no"]
    r = subprocess.run(cmd, cwd=p, capture_output=True, text=True)
    print(r.stdout)
    if r.returncode != 0:
        print(r.stderr)
        return 1
    print("Meshtastic smoke test: PASSED (proto, gatt, bridge, LCI covered)")
    return 0
if __name__ == "__main__":
    sys.exit(main())
