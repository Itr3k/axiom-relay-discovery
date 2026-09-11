import json
import sys
from pathlib import Path
from . import parse_mer_json, verify_mer


def main():
    args = sys.argv[1:]
    if len(args) not in (3, 4) or args[0] != "verify":
        print("Usage: axiom-mer verify RECEIPT.json TRUST.json [VERIFICATION_TIME]", file=sys.stderr)
        return 2
    try:
        envelope = parse_mer_json(Path(args[1]).read_text(encoding="utf-8"))
        keys = parse_mer_json(Path(args[2]).read_text(encoding="utf-8"))
        result = verify_mer(envelope, trusted_keys=keys, verification_time=args[3] if len(args) == 4 else None)
        print(json.dumps(result, indent=2))
        return 0 if result["valid"] else 1
    except (ValueError, TypeError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
