#!/usr/bin/env python3
"""
Generate Helper <-> ProgType mappings matching dependency/func_prog.json format.

Steps:
- Run scan.py (or read existing scan JSON)
- Run resolve_mapping to compute prog type -> helpers
- Invert to helper -> prog types, drop BPF_FUNC_unspec
- Write generated JSON (separate file) and print diff vs dependency/func_prog.json
"""
import argparse
import difflib
import json
import os
import sys
from collections import defaultdict, OrderedDict
from typing import Dict, List, Set

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import scan  # type: ignore
import resolve_mapping  # type: ignore


def invert_mapping(prog_type_helpers: Dict[str, Dict[str, str]], helper_order: List[str] = None) -> Dict[str, List[str]]:
    helper_to_prog: Dict[str, Set[str]] = defaultdict(set)
    for prog_type, helpers in prog_type_helpers.items():
        for helper in helpers:
            if helper == "BPF_FUNC_unspec":
                continue
            helper_to_prog[helper].add(prog_type)
    ordered = OrderedDict()
    if helper_order:
        for helper in helper_order:
            if helper in helper_to_prog:
                ordered[helper] = sorted(helper_to_prog[helper])
    for helper in sorted(helper_to_prog.keys()):
        if helper not in ordered:
            ordered[helper] = sorted(helper_to_prog[helper])
    return ordered


def load_existing_mapping(path: str) -> Dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_helper_order(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return list(data.keys())


def dump_json(data: Dict) -> str:
    return json.dumps(data, indent=4)


def run_pipeline(kernel_dir: str, scan_json: str = None) -> Dict:
    if scan_json and os.path.exists(scan_json):
        with open(scan_json, "r", encoding="utf-8") as f:
            scan_data = json.load(f)
    else:
        scan_data = scan.scan_kernel(kernel_dir)
    helpers = resolve_mapping.parse_enum_constants(kernel_dir, "bpf_func_id", "BPF_FUNC_")
    if not helpers:
        helpers = resolve_mapping.collect_helpers_from_scan(scan_data)
    arrays = resolve_mapping.build_array_mapping(scan_data)
    analyses = resolve_mapping.build_function_analysis(scan_data)
    prog_type_helpers, unresolved = resolve_mapping.build_progtype_to_helpers(
        scan_data, analyses, arrays, helpers
    )
    return {
        "prog_type_helpers": prog_type_helpers,
        "unresolved": unresolved,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Helper<->ProgType mapping file.")
    parser.add_argument("kernel_dir", help="Kernel source directory")
    parser.add_argument("--scan-json", help="Existing scan output from scan.py", default=None)
    parser.add_argument(
        "--output", "-o", default="output/bpf_mappings/func_prog.generated.json", help="Where to write generated mapping"
    )
    parser.add_argument(
        "--helper-order", default="dependency/helper_def.json", help="JSON file whose keys provide helper ordering"
    )
    args = parser.parse_args()

    result = run_pipeline(args.kernel_dir, args.scan_json)
    helper_order = load_helper_order(args.helper_order)
    helper_to_prog = invert_mapping(result["prog_type_helpers"], helper_order if helper_order else None)

    out_dir = os.path.dirname(os.path.abspath(args.output))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(dump_json(helper_to_prog))


if __name__ == "__main__":
    main()
