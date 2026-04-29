"""
eBPF Documentation Loader for ChromaDB

This module loads parsed eBPF helper documentation into ChromaDB vector database
for efficient retrieval and RAG (Retrieval-Augmented Generation) applications.
"""

import chromadb
from chromadb.config import Settings
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from tqdm import tqdm
import json

try:
    from .ebpf_doc_parser import HelperDocParser
except ImportError:
    from ebpf_doc_parser import HelperDocParser


class EBPFDocLoader:
    """
    Loads eBPF helper documentation into ChromaDB.

    This class combines the HelperDocParser and ChromaDB to create a searchable
    vector database of eBPF helper function documentation.
    """

    def __init__(
        self,
        chroma_db_path: str = None,
        docs_root: str = None,
        collection_name: str = "ebpf_helpers"
    ):
        """
        Initialize the document loader.

        Args:
            chroma_db_path: Path to store the ChromaDB database.
                           If None, defaults to PROJECT_ROOT/menu/utils/chroma_db
            docs_root: Path to the eBPF documentation directory.
                      If None, defaults to PROJECT_ROOT/ebpf-docs/docs/linux/helper-function
            collection_name: Name of the ChromaDB collection
        """
        # Calculate default paths relative to project root
        # Current file: PROJECT_ROOT/menu/utils/ebpf_doc_loader.py
        project_root = Path(__file__).parent.parent.parent

        if chroma_db_path is None:
            chroma_db_path = Path(__file__).parent / "chroma_db"

        if docs_root is None:
            docs_root = project_root / "ebpf-docs/docs/linux/helper-function"

        self.chroma_db_path = Path(chroma_db_path)
        self.docs_root = docs_root
        self.collection_name = collection_name

        # Initialize parser
        self.parser = HelperDocParser(docs_root=docs_root)

        # Initialize ChromaDB client
        self.client = None
        self.collection = None

    def initialize_chroma_db(self, reset: bool = False):
        """
        Initialize ChromaDB client and collection.

        Args:
            reset: If True, delete existing collection and create new one
        """
        print(f"Initializing ChromaDB at: {self.chroma_db_path}")

        # Create directory if it doesn't exist
        self.chroma_db_path.mkdir(parents=True, exist_ok=True)

        # Create client
        self.client = chromadb.PersistentClient(path=str(self.chroma_db_path))

        # Handle collection
        if reset:
            try:
                self.client.delete_collection(name=self.collection_name)
                print(f"  Deleted existing collection: {self.collection_name}")
            except:
                pass

        # Create or get collection
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"description": "eBPF helper function documentation for RAG"}
        )

        print(f"  Collection ready: {self.collection_name}")
        print(f"  Existing documents: {self.collection.count()}")

    def _prepare_document_for_chroma(self, helper_name: str, parsed_doc: Dict) -> Tuple[str, Dict, str]:
        """
        Prepare a single parsed document for ChromaDB insertion.

        Args:
            helper_name: Name of the helper function
            parsed_doc: Parsed document dictionary from HelperDocParser

        Returns:
            Tuple of (document_text, metadata, document_id)
        """
        # Use full markdown content as the document text for embedding
        document_text = parsed_doc["full_content"]

        # Prepare metadata (ChromaDB doesn't accept None values)
        kernel_ver = parsed_doc.get("kernel_version")
        metadata = {
            "helper_name": helper_name,
            "kernel_version": kernel_ver if kernel_ver else "unknown",
            "has_example": len(parsed_doc.get("example", "")) > 0,
            "num_program_types": len(parsed_doc.get("program_types", [])),
            "num_map_types": len(parsed_doc.get("map_types", [])),
            "has_dependencies": len(parsed_doc.get("dependencies", {}).get("required_helpers", [])) > 0,
        }

        # Add program types as comma-separated string (for filtering)
        prog_types = parsed_doc.get("program_types", [])
        if prog_types:
            metadata["program_types"] = ",".join(prog_types[:5])  # First 5 to avoid metadata size limits
        else:
            metadata["program_types"] = ""

        # Add required helpers as comma-separated string
        req_helpers = parsed_doc.get("dependencies", {}).get("required_helpers", [])
        if req_helpers:
            metadata["required_helpers"] = ",".join(req_helpers)
        else:
            metadata["required_helpers"] = ""

        # Categorize helper by name patterns
        category = self._categorize_helper(helper_name)
        metadata["category"] = category

        # Use helper name as document ID
        document_id = helper_name

        return document_text, metadata, document_id

    def _categorize_helper(self, helper_name: str) -> str:
        """
        Categorize helper function by name patterns.

        Args:
            helper_name: Name of the helper function

        Returns:
            Category string
        """
        name_lower = helper_name.lower()

        if "map_" in name_lower:
            return "map_operations"
        elif "sk_" in name_lower or "sock" in name_lower:
            return "socket"
        elif "probe_read" in name_lower or "probe_write" in name_lower:
            return "memory"
        elif "trace" in name_lower or "printk" in name_lower:
            return "tracing"
        elif "timer" in name_lower:
            return "timer"
        elif "dynptr" in name_lower:
            return "dynptr"
        elif "ringbuf" in name_lower:
            return "ringbuf"
        elif "csum" in name_lower or "fib" in name_lower or "redirect" in name_lower:
            return "networking"
        elif "task" in name_lower or "cgroup" in name_lower:
            return "process"
        else:
            return "other"

    def load_all_helpers(self, batch_size: int = 50, show_progress: bool = True) -> Dict:
        """
        Load all helper function documentation into ChromaDB.

        Args:
            batch_size: Number of documents to add in each batch
            show_progress: Whether to show progress bar

        Returns:
            Dictionary with loading statistics
        """
        if self.collection is None:
            raise RuntimeError("ChromaDB not initialized. Call initialize_chroma_db() first.")

        print("\nParsing all helper documentation...")
        all_helpers = self.parser.parse_all_helpers()
        total_helpers = len(all_helpers)

        print(f"Found {total_helpers} helper functions")
        print("\nLoading into ChromaDB...")

        # Prepare batches
        documents_batch = []
        metadatas_batch = []
        ids_batch = []

        stats = {
            "total_helpers": total_helpers,
            "loaded": 0,
            "failed": 0,
            "skipped": 0,
            "categories": {},
        }

        # Use tqdm for progress bar
        iterator = tqdm(all_helpers.items(), disable=not show_progress, desc="Loading helpers")

        for helper_name, parsed_doc in iterator:
            try:
                # Prepare document
                doc_text, metadata, doc_id = self._prepare_document_for_chroma(helper_name, parsed_doc)

                # Add to batch
                documents_batch.append(doc_text)
                metadatas_batch.append(metadata)
                ids_batch.append(doc_id)

                # Track category stats
                category = metadata.get("category", "other")
                stats["categories"][category] = stats["categories"].get(category, 0) + 1

                # Insert batch when it reaches batch_size
                if len(documents_batch) >= batch_size:
                    self.collection.add(
                        documents=documents_batch,
                        metadatas=metadatas_batch,
                        ids=ids_batch
                    )
                    stats["loaded"] += len(documents_batch)

                    # Clear batches
                    documents_batch = []
                    metadatas_batch = []
                    ids_batch = []

            except Exception as e:
                stats["failed"] += 1
                print(f"\n  Error loading {helper_name}: {e}")

        # Insert remaining documents
        if documents_batch:
            try:
                self.collection.add(
                    documents=documents_batch,
                    metadatas=metadatas_batch,
                    ids=ids_batch
                )
                stats["loaded"] += len(documents_batch)
            except Exception as e:
                stats["failed"] += len(documents_batch)
                print(f"\n  Error loading final batch: {e}")

        return stats

    def get_stats(self) -> Dict:
        """
        Get statistics about the loaded documentation.

        Returns:
            Dictionary with statistics
        """
        if self.collection is None:
            return {"error": "ChromaDB not initialized"}

        count = self.collection.count()

        # Get sample metadata to analyze
        sample = self.collection.get(limit=count)

        stats = {
            "total_documents": count,
            "collection_name": self.collection_name,
            "db_path": str(self.chroma_db_path),
        }

        # Analyze categories
        categories = {}
        for metadata in sample.get("metadatas", []):
            category = metadata.get("category", "other")
            categories[category] = categories.get(category, 0) + 1
        stats["categories"] = categories

        # Count helpers with examples
        with_examples = sum(1 for m in sample.get("metadatas", []) if m.get("has_example", False))
        stats["helpers_with_examples"] = with_examples

        # Count helpers with dependencies
        with_deps = sum(1 for m in sample.get("metadatas", []) if m.get("has_dependencies", False))
        stats["helpers_with_dependencies"] = with_deps

        return stats

    def test_query(self, query_text: str, n_results: int = 3) -> Dict:
        """
        Test query to verify the database works.

        Args:
            query_text: Query string
            n_results: Number of results to return

        Returns:
            Query results dictionary
        """
        if self.collection is None:
            raise RuntimeError("ChromaDB not initialized")

        results = self.collection.query(
            query_texts=[query_text],
            n_results=n_results
        )

        return results

    def get_helper_by_name(self, helper_name: str) -> Optional[Dict]:
        """
        Get a specific helper by exact name match.

        Args:
            helper_name: Name of the helper function

        Returns:
            Dictionary with helper information or None if not found
        """
        if self.collection is None:
            raise RuntimeError("ChromaDB not initialized")

        try:
            results = self.collection.get(ids=[helper_name])

            if results["ids"]:
                return {
                    "id": results["ids"][0],
                    "document": results["documents"][0],
                    "metadata": results["metadatas"][0],
                }
            return None
        except Exception as e:
            print(f"Error retrieving {helper_name}: {e}")
            return None

    def save_stats_to_file(self, filepath: str):
        """
        Save database statistics to a JSON file.

        Args:
            filepath: Path to save the stats file
        """
        stats = self.get_stats()

        with open(filepath, 'w') as f:
            json.dump(stats, f, indent=2)

        print(f"Stats saved to: {filepath}")


def build_ebpf_knowledge_base(reset: bool = False):
    """
    Convenience function to build the complete eBPF knowledge base.

    Args:
        reset: Whether to reset existing database

    Returns:
        EBPFDocLoader instance with loaded database
    """
    print("="*60)
    print("Building eBPF Knowledge Base")
    print("="*60)

    # Initialize loader
    loader = EBPFDocLoader()

    # Initialize database
    loader.initialize_chroma_db(reset=reset)

    # Check if already loaded
    if loader.collection.count() > 0 and not reset:
        print(f"\nDatabase already contains {loader.collection.count()} documents.")
        print("Use reset=True to rebuild from scratch.")
        return loader

    # Load all helpers
    stats = loader.load_all_helpers(batch_size=50, show_progress=True)

    # Print statistics
    print("\n" + "="*60)
    print("Loading Complete!")
    print("="*60)
    print(f"Total helpers: {stats['total_helpers']}")
    print(f"Successfully loaded: {stats['loaded']}")
    print(f"Failed: {stats['failed']}")
    print(f"\nCategories:")
    for category, count in sorted(stats['categories'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {category:20s}: {count:3d}")

    # Get detailed stats
    detailed_stats = loader.get_stats()
    print(f"\nHelpers with examples: {detailed_stats['helpers_with_examples']}")
    print(f"Helpers with dependencies: {detailed_stats['helpers_with_dependencies']}")

    # Test query
    print("\n" + "="*60)
    print("Testing Query")
    print("="*60)
    test_results = loader.test_query("How do I lookup values from a BPF map?", n_results=3)

    print(f"Query: 'How do I lookup values from a BPF map?'")
    print(f"Top 3 results:")
    for i, (helper_id, distance) in enumerate(zip(test_results['ids'][0], test_results['distances'][0])):
        print(f"  {i+1}. {helper_id} (distance: {distance:.4f})")

    print("\n" + "="*60)
    print("✅ eBPF Knowledge Base Ready!")
    print("="*60)

    return loader


if __name__ == "__main__":
    # Build the knowledge base
    loader = build_ebpf_knowledge_base(reset=True)

    # Save stats (use relative path)
    stats_file = Path(__file__).parent / "ebpf_kb_stats.json"
    loader.save_stats_to_file(str(stats_file))
