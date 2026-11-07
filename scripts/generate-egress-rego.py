#!/usr/bin/env python3
"""Write tests/security/policies/egress_services.rego from selfhost/chronicle_ops/services.py.

The conftest policy reads which networks are internal and which services are edges from that
generated module, so the Compose policy and the operator's verify use one list.

    python3 scripts/generate-egress-rego.py           # rewrite the module
    python3 scripts/generate-egress-rego.py --check   # exit 1 when it is out of date
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests/security/policies/egress_services.rego"
sys.path.insert(0, str(ROOT / "selfhost"))

from chronicle_ops.services import rego_module


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail when the committed module differs")
    arguments = parser.parse_args()
    wanted = rego_module()
    if arguments.check:
        if not TARGET.is_file() or TARGET.read_text(encoding="utf-8") != wanted:
            print(f"{TARGET.relative_to(ROOT)} is out of date; run python3 scripts/generate-egress-rego.py",
                  file=sys.stderr)
            return 1
        return 0
    TARGET.write_text(wanted, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
