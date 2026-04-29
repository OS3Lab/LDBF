#!/usr/bin/env python3
"""
Scan a kernel source tree for BPF verifier/get_func_proto relationships.

Outputs a JSON summary containing:
- struct bpf_verifier_ops definitions and their .get_func_proto targets
- functions returning struct bpf_func_proto *
- struct bpf_func_proto initializers
- arrays of struct bpf_func_proto * indexed by BPF_FUNC_*
- mappings from enum bpf_prog_type to verifier_ops (from bpf_verifier_ops[] arrays)
"""
import argparse
import json
import os
import re
import sys
from typing import Dict, Iterable, List, Optional, Tuple


IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".repo",
    "Documentation",
    "samples",
    "tools",
    "usr",
    "output",
    "out",
    "build",
    "kconfig",
    "drivers/staging/media",
}


def iter_source_files(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored dirs early
        dirnames[:] = [d for d in dirnames if not should_skip_dir(os.path.join(dirpath, d))]
        for name in filenames:
            if name.endswith((".c", ".h")):
                yield os.path.join(dirpath, name)


def should_skip_dir(path: str) -> bool:
    base = os.path.basename(path)
    if base in IGNORED_DIRS:
        return True
    if base.startswith(".git"):
        return True
    return False


def load_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def find_block(text: str, start: int) -> Optional[Tuple[int, int]]:
    """Given index of '{', find matching '}' position (inclusive)."""
    if start < 0 or start >= len(text) or text[start] != "{":
        return None
    depth = 0
    for idx in range(start, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return start, idx
    return None


def add_line_number(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def extract_verifier_ops(text: str, path: str) -> List[Dict]:
    results = []
    pattern = re.compile(r"(?:const\s+)?struct\s+bpf_verifier_ops\s+(\w+)\s*=")
    for m in pattern.finditer(text):
        name = m.group(1)
        brace_start = text.find("{", m.end())
        if brace_start == -1:
            continue
        block = find_block(text, brace_start)
        if not block:
            continue
        _, end = block
        body = text[brace_start : end + 1]
        get_proto_match = re.search(r"\.get_func_proto\s*=\s*([^\s,}]+)", body)
        get_proto = get_proto_match.group(1) if get_proto_match else None
        results.append(
            {
                "name": name,
                "file": path,
                "line": add_line_number(text, m.start()),
                "get_func_proto": get_proto,
            }
        )
    return results


def extract_func_proto_structs(text: str, path: str) -> List[Dict]:
    results = []
    pattern = re.compile(r"\bstruct\s+bpf_func_proto\b[^{;=]*\b(\w+)\b\s*=\s*{")
    for m in pattern.finditer(text):
        name = m.group(1)
        results.append({"name": name, "file": path, "line": add_line_number(text, m.start())})
    return results


def extract_func_proto_arrays(text: str, path: str) -> List[Dict]:
    results = []
    pattern = re.compile(
        r"\bstruct\s+bpf_func_proto\s*\*\s*const\s+(\w+)\s*\[\s*\]\s*=\s*{", re.MULTILINE
    )
    for m in pattern.finditer(text):
        name = m.group(1)
        brace_start = text.find("{", m.end() - 1)
        block = find_block(text, brace_start)
        init_text = text[brace_start : block[1] + 1] if block else ""
        entries = extract_helper_array_entries(init_text)
        results.append(
            {
                "name": name,
                "file": path,
                "line": add_line_number(text, m.start()),
                "entries": entries,
            }
        )
    return results


def extract_helper_array_entries(init_text: str) -> Dict[str, str]:
    entries: Dict[str, str] = {}
    pattern = re.compile(r"\[\s*(BPF_FUNC_[A-Za-z0-9_]+)\s*\]\s*=\s*&?(\w+)")
    for m in pattern.finditer(init_text):
        entries[m.group(1)] = m.group(2)
    return entries


def extract_proto_functions(text: str, path: str) -> List[Dict]:
    results = []
    # Allow attributes between type and name
    pattern = re.compile(
        r"([a-zA-Z0-9_\s\*]*struct\s+bpf_func_proto\s*\*\s*)(\w+)\s*\([^;{]*\)\s*{",
        re.MULTILINE,
    )
    for m in pattern.finditer(text):
        name = m.group(2)
        brace_start = text.find("{", m.end() - 1)
        block = find_block(text, brace_start)
        body = text[brace_start : block[1] + 1] if block else ""
        results.append(
            {
                "name": name,
                "file": path,
                "line": add_line_number(text, m.start()),
                "body": body,
            }
        )
    return results


def extract_progtype_mappings(text: str, path: str) -> List[Dict]:
    if "bpf_verifier_ops" not in text:
        return []
    results: List[Dict] = []
    array_pat = re.compile(r"bpf_verifier_ops\s*\[\s*\]\s*=\s*{", re.MULTILINE)
    for m in array_pat.finditer(text):
        brace_start = text.find("{", m.end() - 1)
        block = find_block(text, brace_start)
        if not block:
            continue
        init = text[brace_start : block[1] + 1]
        entry_pat = re.compile(r"\[\s*(BPF_PROG_TYPE_[A-Z0-9_]+)\s*\]\s*=\s*&?(\w+)")
        for em in entry_pat.finditer(init):
            results.append(
                {
                    "prog_type": em.group(1),
                    "verifier_ops": em.group(2),
                    "file": path,
                    "line": add_line_number(text, m.start() + em.start()),
                }
            )
    return results


def extract_progtype_macros(text: str, path: str) -> List[Dict]:
    results: List[Dict] = []
    pattern = re.compile(r"BPF_PROG_TYPE\s*\(\s*(BPF_PROG_TYPE_[A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)")
    for m in pattern.finditer(text):
        prog_type = m.group(1)
        name = m.group(2)
        results.append(
            {
                "prog_type": prog_type,
                "verifier_ops": f"{name}_verifier_ops",
                "file": path,
                "line": add_line_number(text, m.start()),
            }
        )
    return results


def extract_struct_ops(text: str, path: str) -> List[Dict]:
    results = []
    pattern = re.compile(r"(?:static\s+)?(?:const\s+)?struct\s+bpf_struct_ops\s+(\w+)\s*=\s*{")
    for m in pattern.finditer(text):
        name = m.group(1)
        brace_start = text.find("{", m.end() - 1)
        block = find_block(text, brace_start)
        if not block:
            continue
        body = text[brace_start : block[1] + 1]
        verifier_match = re.search(r"\.verifier_ops\s*=\s*&?(\w+)", body)
        verifier_ops = verifier_match.group(1) if verifier_match else None
        results.append(
            {
                "name": name,
                "verifier_ops": verifier_ops,
                "file": path,
                "line": add_line_number(text, m.start()),
            }
        )
    return results


def scan_kernel(root: str) -> Dict:
    verifier_ops = []
    func_proto_structs = []
    func_proto_arrays = []
    proto_functions = []
    progtype_maps = []
    progtype_macros = []
    struct_ops = []

    for path in iter_source_files(root):
        text = load_text(path)
        if not text:
            continue
        verifier_ops.extend(extract_verifier_ops(text, path))
        func_proto_structs.extend(extract_func_proto_structs(text, path))
        func_proto_arrays.extend(extract_func_proto_arrays(text, path))
        proto_functions.extend(extract_proto_functions(text, path))
        progtype_maps.extend(extract_progtype_mappings(text, path))
        progtype_macros.extend(extract_progtype_macros(text, path))
        struct_ops.extend(extract_struct_ops(text, path))

    return {
        "verifier_ops": verifier_ops,
        "func_proto_structs": func_proto_structs,
        "func_proto_arrays": func_proto_arrays,
        "proto_functions": proto_functions,
        "progtype_maps": progtype_maps + progtype_macros,
        "struct_ops": struct_ops,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan kernel tree for BPF func protos and verifier ops.")
    parser.add_argument("kernel_dir", help="Path to kernel source directory to scan")
    parser.add_argument(
        "--output", "-o", default=None, help="Optional JSON output path (defaults to stdout if omitted)"
    )
    args = parser.parse_args()

    data = scan_kernel(args.kernel_dir)
    if args.output:
        out_dir = os.path.dirname(os.path.abspath(args.output))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    else:
        json.dump(data, fp=sys.stdout, indent=2)


if __name__ == "__main__":
    main()
