"""
eBPF Documentation Parser

This module parses eBPF helper function documentation from the local ebpf-docs repository.
It extracts structured information including definitions, usage, examples, and dependencies.
"""

import re
import os
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class HelperDocParser:
    """Parser for eBPF helper function documentation."""

    def __init__(self, docs_root: str = None):
        """
        Initialize the parser.

        Args:
            docs_root: Path to the helper function documentation directory.
                      If None, defaults to PROJECT_ROOT/ebpf-docs/docs/linux/helper-function
        """
        if docs_root is None:
            # Calculate default path relative to project root
            # Current file: PROJECT_ROOT/menu/utils/ebpf_doc_parser.py
            project_root = Path(__file__).parent.parent.parent
            docs_root = project_root / "ebpf-docs/docs/linux/helper-function"

        self.docs_root = Path(docs_root)
        if not self.docs_root.exists():
            raise ValueError(f"Documentation directory not found: {docs_root}")

    def parse_helper_doc(self, helper_name: str) -> Optional[Dict]:
        """
        Parse a single helper function documentation file.

        Args:
            helper_name: Name of the helper function (e.g., "bpf_map_lookup_elem")

        Returns:
            Dictionary containing structured information, or None if file not found
        """
        # Construct file path
        doc_file = self.docs_root / f"{helper_name}.md"

        if not doc_file.exists():
            return None

        # Read the entire file
        with open(doc_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Extract structured information
        result = {
            "helper_name": helper_name,
            "full_content": content,
            "metadata": self._extract_metadata(content),
            "kernel_version": self._extract_kernel_version(content),
            "definition": self._extract_definition(content),
            "usage": self._extract_usage(content),
            "program_types": self._extract_program_types(content),
            "map_types": self._extract_map_types(content),
            "example": self._extract_example(content),
            "dependencies": self._analyze_dependencies(content),
        }

        return result

    def _extract_metadata(self, content: str) -> Dict:
        """Extract YAML frontmatter metadata."""
        metadata = {}

        # Match YAML frontmatter (between --- markers)
        frontmatter_match = re.search(r'^---\s*\n(.*?)\n---', content, re.MULTILINE | re.DOTALL)
        if frontmatter_match:
            yaml_content = frontmatter_match.group(1)

            # Extract title
            title_match = re.search(r'title:\s*"(.+?)"', yaml_content)
            if title_match:
                metadata['title'] = title_match.group(1)

            # Extract description
            desc_match = re.search(r'description:\s*"(.+?)"', yaml_content)
            if desc_match:
                metadata['description'] = desc_match.group(1)

        return metadata

    def _extract_kernel_version(self, content: str) -> Optional[str]:
        """Extract kernel version information."""
        # Look for version tag like [:octicons-tag-24: v3.18]
        version_match = re.search(r'\[:octicons-tag-24:\s*(v[\d.]+)\]', content)
        if version_match:
            return version_match.group(1)
        return None

    def _extract_definition(self, content: str) -> Dict:
        """Extract helper function definition section."""
        definition = {
            "description": "",
            "returns": "",
            "signature": ""
        }

        # Extract content between [HELPER_FUNC_DEF] markers
        def_match = re.search(
            r'<!-- \[HELPER_FUNC_DEF\] -->(.*?)<!-- \[/HELPER_FUNC_DEF\] -->',
            content,
            re.DOTALL
        )

        if def_match:
            def_content = def_match.group(1).strip()

            # Split by ### Returns to separate description and returns
            parts = re.split(r'###\s+Returns\s*\n', def_content)

            if len(parts) > 0:
                definition["description"] = parts[0].strip()

            if len(parts) > 1:
                returns_and_sig = parts[1].strip()

                # Extract signature (C code in backticks)
                sig_match = re.search(r'`#!c\s+(.+?)`', returns_and_sig, re.DOTALL)
                if sig_match:
                    definition["signature"] = sig_match.group(1).strip()
                    # Returns is the text before the signature
                    definition["returns"] = returns_and_sig[:sig_match.start()].strip()
                else:
                    definition["returns"] = returns_and_sig

        return definition

    def _extract_usage(self, content: str) -> Dict:
        """Extract usage section."""
        usage = {
            "description": "",
            "warnings": [],
            "notes": []
        }

        # Find Usage section
        usage_match = re.search(
            r'##\s+Usage\s*\n(.*?)(?=##|\Z)',
            content,
            re.DOTALL
        )

        if usage_match:
            usage_content = usage_match.group(1).strip()

            # Extract main description (text before subsections)
            main_desc_match = re.search(
                r'^(.*?)(?=###|\Z)',
                usage_content,
                re.DOTALL
            )
            if main_desc_match:
                usage["description"] = main_desc_match.group(1).strip()

            # Extract warnings (content in !!! warning blocks)
            warnings = re.findall(
                r'!!!\s+warning\s*\n\s*(.*?)(?=\n\n|\n!!!|\Z)',
                usage_content,
                re.DOTALL
            )
            usage["warnings"] = [w.strip() for w in warnings]

            # Extract notes (content in !!! note or !!! info blocks)
            notes = re.findall(
                r'!!!\s+(?:note|info)\s*\n\s*(.*?)(?=\n\n|\n!!!|\Z)',
                usage_content,
                re.DOTALL
            )
            usage["notes"] = [n.strip() for n in notes]

        return usage

    def _extract_program_types(self, content: str) -> List[str]:
        """Extract supported program types."""
        program_types = []

        # Find Program types section
        prog_section = re.search(
            r'###\s+Program types\s*\n.*?\[HELPER_FUNC_PROG_REF\](.*?)\[/HELPER_FUNC_PROG_REF\]',
            content,
            re.DOTALL
        )

        if prog_section:
            # Extract program type names from markdown links
            # Pattern: [`BPF_PROG_TYPE_XDP`](...)
            types = re.findall(r'\[`(BPF_PROG_TYPE_\w+)`\]', prog_section.group(1))
            program_types = types

        return program_types

    def _extract_map_types(self, content: str) -> List[str]:
        """Extract supported map types."""
        map_types = []

        # Find Map types section
        map_section = re.search(
            r'###\s+Map types\s*\n.*?\[HELPER_FUNC_MAP_REF\](.*?)\[/HELPER_FUNC_MAP_REF\]',
            content,
            re.DOTALL
        )

        if map_section:
            # Extract map type names from markdown links
            # Pattern: [`BPF_MAP_TYPE_HASH`](...)
            types = re.findall(r'\[`(BPF_MAP_TYPE_\w+)`\]', map_section.group(1))
            map_types = types

        return map_types

    def _extract_example(self, content: str) -> str:
        """Extract example code."""
        # Find Example section
        example_match = re.search(
            r'###\s+Example\s*\n.*?```c\s*\n(.*?)```',
            content,
            re.DOTALL
        )

        if example_match:
            return example_match.group(1).strip()

        return ""

    def _analyze_dependencies(self, content: str) -> Dict:
        """
        Analyze helper dependencies from documentation.

        This extracts:
        1. Explicit dependencies mentioned in text (e.g., "must be released via bpf_sk_release")
        2. Helper functions referenced in examples
        """
        dependencies = {
            "required_helpers": [],  # Helpers that must be called (e.g., release functions)
            "related_helpers": [],   # Helpers mentioned in examples or usage
        }

        # Pattern 1: Explicit "must be released via" or "should be used with"
        release_patterns = [
            r'released via \*\*(\w+)\*\*',
            r'must be released via \*\*(\w+)\*\*',
            r'should be released via \*\*(\w+)\*\*',
        ]

        for pattern in release_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if match.startswith('bpf_') and match not in dependencies["required_helpers"]:
                    dependencies["required_helpers"].append(match)

        # Pattern 2: Extract helper calls from example code
        example = self._extract_example(content)
        if example:
            # Find all bpf_ function calls
            helper_calls = re.findall(r'\b(bpf_\w+)\s*\(', example)
            for helper in helper_calls:
                if helper not in dependencies["related_helpers"]:
                    dependencies["related_helpers"].append(helper)

        return dependencies

    def parse_all_helpers(self) -> Dict[str, Dict]:
        """
        Parse all helper function documentation files.

        Returns:
            Dictionary mapping helper names to their parsed documentation
        """
        all_helpers = {}

        # Iterate through all .md files in the directory
        for doc_file in self.docs_root.glob("*.md"):
            helper_name = doc_file.stem  # Filename without extension

            parsed_doc = self.parse_helper_doc(helper_name)
            if parsed_doc:
                all_helpers[helper_name] = parsed_doc

        return all_helpers

    def get_helper_summary(self, helper_name: str) -> Optional[str]:
        """
        Get a concise summary of a helper function for prompt injection.

        Args:
            helper_name: Name of the helper function

        Returns:
            Formatted summary string suitable for LLM prompt
        """
        doc = self.parse_helper_doc(helper_name)
        if not doc:
            return None

        summary_parts = []

        # Header
        summary_parts.append(f"## Helper: {helper_name}")

        # Kernel version
        if doc["kernel_version"]:
            summary_parts.append(f"**Introduced in**: {doc['kernel_version']}")

        # Description
        if doc["definition"]["description"]:
            summary_parts.append(f"\n**Description**: {doc['definition']['description']}")

        # Signature
        if doc["definition"]["signature"]:
            summary_parts.append(f"\n**Signature**:\n```c\n{doc['definition']['signature']}\n```")

        # Returns
        if doc["definition"]["returns"]:
            summary_parts.append(f"\n**Returns**: {doc['definition']['returns']}")

        # Usage
        if doc["usage"]["description"]:
            summary_parts.append(f"\n**Usage Notes**: {doc['usage']['description'][:300]}...")

        # Warnings
        if doc["usage"]["warnings"]:
            summary_parts.append(f"\n**Warnings**:")
            for warning in doc["usage"]["warnings"]:
                summary_parts.append(f"- {warning[:200]}...")

        # Dependencies
        if doc["dependencies"]["required_helpers"]:
            summary_parts.append(f"\n**Required helpers**: {', '.join(doc['dependencies']['required_helpers'])}")

        # Example (truncated)
        if doc["example"]:
            example_lines = doc["example"].split('\n')[:15]  # First 15 lines
            summary_parts.append(f"\n**Example**:\n```c\n" + '\n'.join(example_lines) + "\n...\n```")

        return '\n'.join(summary_parts)


# Utility function for quick testing
def test_parser():
    """Test the parser with a few examples."""
    parser = HelperDocParser()

    # Test helpers
    test_helpers = [
        "bpf_map_lookup_elem",
        "bpf_map_update_elem",
        "bpf_sk_lookup_tcp",
        "bpf_probe_read_kernel"
    ]

    print("Testing eBPF Documentation Parser\n" + "="*50)

    for helper in test_helpers:
        print(f"\nParsing: {helper}")
        doc = parser.parse_helper_doc(helper)

        if doc:
            print(f"  ✓ Kernel version: {doc['kernel_version']}")
            print(f"  ✓ Description length: {len(doc['definition']['description'])} chars")
            print(f"  ✓ Program types: {len(doc['program_types'])} types")
            print(f"  ✓ Map types: {len(doc['map_types'])} types")
            print(f"  ✓ Has example: {len(doc['example']) > 0}")
            print(f"  ✓ Required helpers: {doc['dependencies']['required_helpers']}")
            print(f"  ✓ Related helpers: {doc['dependencies']['related_helpers'][:3]}...")
        else:
            print(f"  ✗ Failed to parse")

    # Test summary generation
    print("\n" + "="*50)
    print("Testing summary generation for bpf_map_lookup_elem:")
    print("="*50)
    summary = parser.get_helper_summary("bpf_map_lookup_elem")
    if summary:
        print(summary)


if __name__ == "__main__":
    test_parser()
