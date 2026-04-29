#!/usr/bin/env python3
"""
Compare two Helper<->ProgType mapping files (func_prog.json style).

Outputs:
- helpers only in left/right
- for shared helpers, added/removed prog types
"""
import argparse
import json
from typing import Dict, List, Set


def load_mapping(path: str) -> Dict[str, List[str]]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def compare(left: Dict[str, List[str]], right: Dict[str, List[str]]) -> str:
    lines: List[str] = []
    left_keys = set(left.keys())
    right_keys = set(right.keys())

    only_left = sorted(left_keys - right_keys)
    only_right = sorted(right_keys - left_keys)
    if only_left:
        lines.append("Helpers only in left (missing in right):")
        for h in only_left:
            lines.append(f"  {h}")
    if only_right:
        lines.append("Helpers only in right (missing in left):")
        for h in only_right:
            lines.append(f"  {h}")

    for helper in sorted(left_keys & right_keys):
        lset: Set[str] = set(left.get(helper, []))
        rset: Set[str] = set(right.get(helper, []))
        added = sorted(rset - lset)
        removed = sorted(lset - rset)
        if added or removed:
            lines.append(f"Helper {helper}:")
            if added:
                lines.append("  + " + ", ".join(added))
            if removed:
                lines.append("  - " + ", ".join(removed))
    if not lines:
        lines.append("No differences.")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare two func_prog.json-style mappings.")
    ap.add_argument("left", help="Baseline mapping (e.g., dependency/func_prog.json)")
    ap.add_argument("right", help="Generated mapping (e.g., output/.../func_prog.generated.json)")
    args = ap.parse_args()

    left = load_mapping(args.left)
    right = load_mapping(args.right)
    report = compare(left, right)
    print(report)


if __name__ == "__main__":
    main()
