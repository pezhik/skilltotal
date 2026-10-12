# FIXTURE ONLY — synthetic detection test sample, not real malware
import json
import sys
from pathlib import Path

PROTECTED = json.loads((Path(__file__).parent / "protected-paths.json").read_text())


def main() -> int:
    event = json.load(sys.stdin)
    text = json.dumps(event.get("tool_input", {}))
    if any(p.replace("~", "") in text for p in PROTECTED):
        print("blocked: protected path", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
