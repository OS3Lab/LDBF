#!/usr/bin/env python3
"""
Resolve prog type -> get_func_proto -> helper mappings using scan results.

Inputs:
- kernel source directory
- optional scan JSON from scan.py (otherwise scan on the fly)

Outputs a JSON summary with:
- prog_type_to_helpers: {prog_type: {helper: proto_name}}
- unresolved: helpers per prog_type that could not be resolved
- function_analysis: intermediate analysis of get_func_proto functions
"""
import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import scan  # type: ignore


Target = Dict[str, Optional[str]]
UNKNOWN = "__UNKNOWN__"


@dataclass
class FunctionAnalysis:
    helper_targets: Dict[str, Target] = field(default_factory=dict)
    fallbacks: List[Target] = field(default_factory=list)
    delegates: Set[str] = field(default_factory=set)
    arrays: Set[str] = field(default_factory=set)


def parse_enum_constants(kernel_dir: str, enum_name: str, prefix: str) -> List[str]:
    candidates = [
        os.path.join(kernel_dir, "include", "uapi", "linux", "bpf.h"),
        os.path.join(kernel_dir, "include", "linux", "bpf.h"),
    ]
    text = ""
    for path in candidates:
        text = scan.load_text(path)
        if text:
            break
    if not text:
        # fallback: search first occurrence anywhere
        for path in scan.iter_source_files(kernel_dir):
            if path.endswith(".h"):
                t = scan.load_text(path)
                if f"enum {enum_name}" in t:
                    text = t
                    break
    if not text:
        return []
    enum_pat = rf"enum\s+{enum_name}\s*{{"
    match = None
    for m in re.finditer(enum_pat, text):
        match = m
        break
    if not match:
        return []
    brace_start = text.find("{", match.end() - 1)
    end = text.find("};", brace_start)
    if brace_start == -1 or end == -1:
        return []
    block_text = text[brace_start + 1 : end]
    constants = []
    for name in re.findall(r"\b([A-Za-z0-9_]+)\b", block_text):
        if name.startswith(prefix):
            constants.append(name)
    return constants


def collect_helpers_from_scan(scan_data: Dict) -> List[str]:
    helpers: Set[str] = set()
    for arr in scan_data.get("func_proto_arrays", []):
        helpers.update(arr.get("entries", {}).keys())
    token_pat = re.compile(r"BPF_FUNC_[A-Za-z0-9_]+")
    for fn in scan_data.get("proto_functions", []):
        body = fn.get("body", "")
        helpers.update(token_pat.findall(body))
    return sorted(helpers)


def parse_return_target(ret_expr: str) -> Target:
    expr = ret_expr.strip().rstrip(";")
    # handle ternary expressions
    if "?" in expr and ":" in expr:
        qpos = expr.find("?")
        cpos = expr.rfind(":")
        if 0 < qpos < cpos:
            true_expr = expr[qpos + 1 : cpos].strip()
            false_expr = expr[cpos + 1 :].strip()
            t_target = parse_return_target(true_expr)
            f_target = parse_return_target(false_expr)
            priorities = {"proto": 0, "delegate": 1, "array": 2, "var": 3, "null": 4}
            candidates = [t_target, f_target]
            candidates = [c for c in candidates if c]
            if candidates:
                best = sorted(candidates, key=lambda c: priorities.get(c.get("kind"), 9))[0]
                return best
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr) and expr in {"fn", "func_proto", "proto", "func"}:
        return {"kind": "var", "value": expr}
    if expr.startswith("&"):
        return {"kind": "proto", "value": expr.lstrip("&").strip()}
    if "[" in expr and "func_id" in expr:
        arr = expr.split("[", 1)[0].strip()
        return {"kind": "array", "value": arr}
    if "(" in expr and expr.split("(", 1)[0].strip():
        func = expr.split("(", 1)[0].strip()
        return {"kind": "delegate", "value": func}
    if expr in ("NULL", "0"):
        return {"kind": "null", "value": None}
    return {"kind": "proto", "value": expr}


def analyze_function(body: str) -> FunctionAnalysis:
    analysis = FunctionAnalysis()
    var_delegates: Dict[str, List[str]] = {}
    assign_pat = re.compile(r"(\w+)\s*=\s*(\w+)\s*\([^;]*func_id")
    for m in assign_pat.finditer(body):
        var = m.group(1)
        target_fn = m.group(2)
        var_delegates.setdefault(var, []).append(target_fn)

    case_pat = re.compile(r"case\s+(BPF_FUNC_[A-Za-z0-9_]+)\s*:\s*")
    cases = list(case_pat.finditer(body))
    boundaries: List[int] = [c.start() for c in cases]
    boundaries.append(len(body))
    for idx, case_match in enumerate(cases):
        helper = case_match.group(1)
        start = case_match.end()
        end = boundaries[idx + 1]
        segment = body[start:end]
        returns = list(re.finditer(r"return\s+([^;]+);", segment))
        chosen_target: Optional[Target] = None
        if returns:
            # prioritize proto > delegate > array > var > null/unknown
            priorities = {"proto": 0, "delegate": 1, "array": 2, "var": 3, "null": 4}
            best = (10, None)
            for m in returns:
                ret_expr = m.group(1)
                target = parse_return_target(ret_expr)
                kind = target.get("kind")
                if kind == "var" and target.get("value") in var_delegates:
                    del_fn = var_delegates[target["value"]][0]
                    target = {"kind": "delegate", "value": del_fn}
                    analysis.delegates.add(del_fn)
                    kind = "delegate"
                prio = priorities.get(kind, 9)
                if prio < best[0]:
                    best = (prio, target)
            if best[1]:
                chosen_target = best[1]
        if not chosen_target:
            # fallback: assignment patterns without return (rare)
            assign_in_case = re.findall(r"(\w+)\s*=\s*&?(\w+)\s*;", segment)
            for var, val in assign_in_case:
                if val.startswith(("bpf_", "sk", "tcp", "sock")):
                    chosen_target = {"kind": "proto", "value": val}
                    break
        if chosen_target:
            analysis.helper_targets[helper] = chosen_target
            if chosen_target["kind"] == "delegate" and chosen_target["value"]:
                analysis.delegates.add(chosen_target["value"])
            if chosen_target["kind"] == "array" and chosen_target["value"]:
                analysis.arrays.add(chosen_target["value"])

    if not analysis.fallbacks:
        ret = find_last_return(body)
        if ret:
            target = parse_return_target(ret)
            if target["kind"] == "var" and target.get("value") in var_delegates:
                for del_fn in var_delegates[target["value"]]:
                    analysis.fallbacks.append({"kind": "delegate", "value": del_fn})
                    analysis.delegates.add(del_fn)
            else:
                analysis.fallbacks.append(target)
                if target["kind"] == "delegate" and target["value"]:
                    analysis.delegates.add(target["value"])
                if target["kind"] == "array" and target["value"]:
                    analysis.arrays.add(target["value"])

    if_pat = re.compile(r"if\s*\(\s*func_id\s*==\s*(BPF_FUNC_[A-Za-z0-9_]+)\s*\)[^{;]*?return\s+([^;]+);")
    for m in if_pat.finditer(body):
        helper = m.group(1)
        ret_expr = m.group(2)
        target = parse_return_target(ret_expr)
        analysis.helper_targets.setdefault(helper, target)
        if target["kind"] == "delegate" and target["value"]:
            analysis.delegates.add(target["value"])
        if target["kind"] == "array" and target["value"]:
            analysis.arrays.add(target["value"])

    var_if_pat = re.compile(r"if\s*\(\s*(\w+)\s*\)\s*return\s+(\w+);")
    for m in var_if_pat.finditer(body):
        var = m.group(2)
        if var in var_delegates:
            for del_fn in var_delegates[var]:
                analysis.fallbacks.append({"kind": "delegate", "value": del_fn})
                analysis.delegates.add(del_fn)

    array_ret_pat = re.compile(r"return\s+(\w+)\s*\[\s*func_id\s*\]", re.MULTILINE)
    for m in array_ret_pat.finditer(body):
        arr = m.group(1)
        target = {"kind": "array", "value": arr}
        analysis.fallbacks.append(target)
        analysis.arrays.add(arr)

    delegate_ret_pat = re.compile(r"return\s+(\w+)\s*\(func_id[^\)]*\)", re.MULTILINE)
    for m in delegate_ret_pat.finditer(body):
        func = m.group(1)
        target = {"kind": "delegate", "value": func}
        analysis.fallbacks.append(target)
        analysis.delegates.add(func)

    return analysis


def find_first_return(segment: str) -> Optional[str]:
    m = re.search(r"return\s+([^;]+);", segment)
    return m.group(1) if m else None


def find_last_return(segment: str) -> Optional[str]:
    matches = list(re.finditer(r"return\s+([^;]+);", segment))
    if not matches:
        return None
    return matches[-1].group(1)


def resolve_helper(
    func_name: str,
    helper: str,
    analyses: Dict[str, FunctionAnalysis],
    arrays: Dict[str, Dict[str, str]],
    memo: Dict[Tuple[str, str], Optional[str]],
    stack: Optional[List[str]] = None,
) -> Optional[str]:
    stack = stack or []
    key = (func_name, helper)
    if key in memo:
        return memo[key]
    if func_name in stack:
        memo[key] = None
        return None
    analysis = analyses.get(func_name)
    if not analysis:
        memo[key] = None
        return None
    stack.append(func_name)
    if helper in analysis.helper_targets:
        target = analysis.helper_targets[helper]
        resolved = resolve_target(target, helper, analyses, arrays, memo, stack)
        memo[key] = resolved
        stack.pop()
        return None if resolved == UNKNOWN else resolved
    for target in analysis.fallbacks:
        resolved = resolve_target(target, helper, analyses, arrays, memo, stack)
        if resolved:
            memo[key] = resolved
            stack.pop()
            return None if resolved == UNKNOWN else resolved
    # explicit miss: treat as not supported (NULL)
    memo[key] = None
    stack.pop()
    return None


def resolve_target(
    target: Target,
    helper: str,
    analyses: Dict[str, FunctionAnalysis],
    arrays: Dict[str, Dict[str, str]],
    memo: Dict[Tuple[str, str], Optional[str]],
    stack: List[str],
) -> Optional[str]:
    kind = target.get("kind")
    value = target.get("value")
    if kind == "proto":
        return value
    if kind == "var":
        return None
    if kind == "delegate" and value:
        res = resolve_helper(value, helper, analyses, arrays, memo, stack)
        return res if res is not None else memo.get((value, helper), None) or res
    if kind == "array" and value:
        arr = arrays.get(value, {})
        if helper in arr:
            return arr.get(helper)
        return UNKNOWN
    if kind == "null":
        return None
    return UNKNOWN


def build_progtype_to_helpers(
    scan_data: Dict,
    analyses: Dict[str, FunctionAnalysis],
    arrays: Dict[str, Dict[str, str]],
    helpers: List[str],
) -> Tuple[Dict[str, Dict[str, str]], Dict[str, List[str]]]:
    ops_lookup = {entry["name"]: entry.get("get_func_proto") for entry in scan_data.get("verifier_ops", [])}
    prog_to_ops: Dict[str, str] = {}
    for entry in scan_data.get("progtype_maps", []):
        prog_to_ops.setdefault(entry["prog_type"], entry["verifier_ops"])

    # collect dynamic struct_ops verifier get_func_proto for STRUCT_OPS
    struct_ops_entries = scan_data.get("struct_ops", [])
    struct_ops_protos = []
    for so in struct_ops_entries:
        vops = so.get("verifier_ops")
        proto_func = ops_lookup.get(vops)
        if proto_func:
            struct_ops_protos.append(proto_func)

    prog_type_helpers: Dict[str, Dict[str, str]] = {}
    unresolved: Dict[str, List[str]] = {}
    memo: Dict[Tuple[str, str], Optional[str]] = {}
    for prog_type, ops in prog_to_ops.items():
        proto_funcs: List[str] = []
        if prog_type == "BPF_PROG_TYPE_STRUCT_OPS" and struct_ops_protos:
            proto_funcs = struct_ops_protos
        else:
            proto = ops_lookup.get(ops)
            if proto:
                proto_funcs = [proto]
            else:
                unresolved[prog_type] = helpers
                continue
        helper_map: Dict[str, str] = {}
        failed_helpers: Set[str] = set()
        for proto_func in proto_funcs:
            for helper in helpers:
                proto = resolve_helper(proto_func, helper, analyses, arrays, memo, stack=[])
                if proto:
                    helper_map[helper] = proto
                elif memo.get((proto_func, helper)) == UNKNOWN:
                    failed_helpers.add(helper)
        prog_type_helpers[prog_type] = helper_map
        unresolved[prog_type] = sorted(failed_helpers)
    return prog_type_helpers, unresolved


def build_function_analysis(scan_data: Dict) -> Dict[str, FunctionAnalysis]:
    analyses: Dict[str, FunctionAnalysis] = {}
    for func in scan_data.get("proto_functions", []):
        name = func["name"]
        body = func.get("body", "")
        analyses[name] = analyze_function(body)
    return analyses


def build_array_mapping(scan_data: Dict) -> Dict[str, Dict[str, str]]:
    arrays: Dict[str, Dict[str, str]] = {}
    for arr in scan_data.get("func_proto_arrays", []):
        arrays[arr["name"]] = arr.get("entries", {})
    return arrays


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve BPF helper mappings per prog type.")
    parser.add_argument("kernel_dir", help="Kernel source directory")
    parser.add_argument("--scan-json", help="Existing scan.json from scan.py", default=None)
    parser.add_argument("--output", "-o", help="Output JSON path", default=None)
    args = parser.parse_args()

    if args.scan_json and os.path.exists(args.scan_json):
        with open(args.scan_json, "r", encoding="utf-8") as f:
            scan_data = json.load(f)
    else:
        scan_data = scan.scan_kernel(args.kernel_dir)

    helpers = parse_enum_constants(args.kernel_dir, "bpf_func_id", "BPF_FUNC_")
    if not helpers:
        helpers = collect_helpers_from_scan(scan_data)
    arrays = build_array_mapping(scan_data)
    analyses = build_function_analysis(scan_data)
    prog_type_helpers, unresolved = build_progtype_to_helpers(scan_data, analyses, arrays, helpers)

    result = {
        "prog_type_to_helpers": prog_type_helpers,
        "unresolved": unresolved,
        "function_analysis": {
            name: {
                "helper_targets": fa.helper_targets,
                "fallbacks": fa.fallbacks,
                "delegates": sorted(fa.delegates),
                "arrays": sorted(fa.arrays),
            }
            for name, fa in analyses.items()
        },
    }

    if args.output:
        out_dir = os.path.dirname(os.path.abspath(args.output))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
    else:
        json.dump(result, fp=sys.stdout, indent=2)


if __name__ == "__main__":
    main()
