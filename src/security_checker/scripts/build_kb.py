"""Knowledge Base Builder — indexes guideline chunks into ChromaDB.

Usage:
    python -m security_checker.scripts.build_kb --rebuild --verify
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
CHUNKS_PATH = PROJECT_ROOT / "knowledge" / "chunks" / "guidelines_chunks.json"
CHROMA_DIR = PROJECT_ROOT / "knowledge" / "chroma_store"
COLLECTION_NAME = "security_guidelines"


def load_chunks() -> list[dict]:
    """Load guideline chunks from JSON file."""
    if not CHUNKS_PATH.exists():
        print(f"ERROR: Chunks file not found at {CHUNKS_PATH}", file=sys.stderr)
        sys.exit(1)
    with open(CHUNKS_PATH) as f:
        data = json.load(f)
    chunks = data.get("chunks", [])
    print(f"Loaded {len(chunks)} guideline chunks from {CHUNKS_PATH.name}")
    return chunks


def build_documents(chunks: list[dict]) -> tuple[list[str], list[str], list[dict]]:
    """Enrich chunk text with metadata for better retrieval."""
    ids, documents, metadatas = [], [], []
    for chunk in chunks:
        lang_str = ", ".join(chunk.get("applies_to", []))
        enriched_text = (
            f"[{chunk['domain']} — {chunk['parent_title']}] "
            f"{chunk['text']} "
            f"Detection patterns: {', '.join(chunk.get('detection_hints', []))} "
            f"Languages: {lang_str}"
        )
        ids.append(chunk["id"])
        documents.append(enriched_text)
        metadatas.append({
            "domain": chunk["domain"],
            "domain_code": chunk["domain_code"],
            "parent_code": chunk["parent_code"],
            "parent_title": chunk["parent_title"],
            "severity": chunk["severity"],
            "applies_to": lang_str,
            "raw_text": chunk["text"],
        })
    return ids, documents, metadatas


def create_collection(ids, documents, metadatas, rebuild=False):
    """Create or update the ChromaDB collection."""
    import chromadb
    from security_checker.embedding_utils import get_embedding_function

    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    embedding_fn = get_embedding_function(verbose=True)
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    if rebuild:
        try:
            client.delete_collection(COLLECTION_NAME)
            print(f"Deleted existing collection: {COLLECTION_NAME}")
        except Exception:
            pass

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_fn,
        metadata={"description": "Organization security guidelines v1.0"},
    )

    if collection.count() > 0 and not rebuild:
        print(f"Collection already has {collection.count()} documents. Use --rebuild to replace.")
        return collection

    batch_size = 50
    for i in range(0, len(ids), batch_size):
        end = min(i + batch_size, len(ids))
        collection.upsert(
            ids=ids[i:end],
            documents=documents[i:end],
            metadatas=metadatas[i:end],
        )
        print(f"  Indexed {end}/{len(ids)} chunks...")

    print(f"Collection '{COLLECTION_NAME}' now has {collection.count()} documents")
    return collection


def verify_knowledge_base(collection):
    """Run test queries to verify retrieval quality."""
    test_queries = [
        ("password hashing MD5 SHA1", ["AU-01.1", "CR-03.1"], "Password hashing → AU-01, CR-03"),
        ("session cookie HttpOnly Secure SameSite", ["SM-04.1", "SM-05.1", "SM-06.1"], "Cookie attrs → SM-04/05/06"),
        ("SQL injection query parameterized", ["IV-05.1"], "SQL injection → IV-05"),
        ("JWT token validation algorithm none", ["AU-11.1", "AU-11.2"], "JWT security → AU-11"),
        ("hardcoded secrets API key password in code", ["CR-05.1"], "Secret storage → CR-05"),
        ("CORS Access-Control-Allow-Origin wildcard", ["SH-07.1", "SH-07.2"], "CORS config → SH-07"),
        ("Content-Security-Policy unsafe-inline unsafe-eval", ["XS-01.1"], "CSP → XS-01"),
        ("pickle deserialization untrusted data", ["IV-09.1"], "Deserialization → IV-09"),
        ("file upload magic bytes validation extension", ["FU-01.1", "FU-01.2"], "File upload → FU-01"),
        ("TLS version SSLv3 TLSv1.0 disabled", ["CR-04.1"], "TLS config → CR-04"),
    ]

    passed = 0
    for query, expected_ids, desc in test_queries:
        results = collection.query(query_texts=[query], n_results=10)
        returned_ids = results["ids"][0] if results["ids"] else []
        expected = set(expected_ids)
        found = expected.intersection(set(returned_ids))
        status = "PASS" if found == expected else "MISS"
        if found == expected:
            passed += 1
        print(f"  [{status}] {desc}: expected {sorted(expected)}, got top-5: {returned_ids[:5]}")

    print(f"\n{passed}/{len(test_queries)} verification queries passed.")
    if passed < len(test_queries):
        print("Tip: Install sentence-transformers for full semantic search:")
        print("  pip install sentence-transformers")


def print_domain_summary(chunks):
    """Print guideline counts by domain."""
    code_counts = {}
    for chunk in chunks:
        code = chunk["domain_code"]
        if code not in code_counts:
            code_counts[code] = (chunk["domain"], 0)
        name, count = code_counts[code]
        code_counts[code] = (name, count + 1)

    total = 0
    print("\nGuideline Chunks by Domain:")
    print(f"  {'Domain':<35} {'Code':<6} {'Count':>5}")
    print(f"  {'-'*35} {'-'*4}   {'-'*5}")
    for code, (name, count) in sorted(code_counts.items()):
        print(f"  {name:<35} {code:<6} {count:>5}")
        total += count
    print(f"  {'TOTAL':<35} {'':6} {total:>5}")


def main():
    parser = argparse.ArgumentParser(description="Build the security guidelines knowledge base")
    parser.add_argument("--verify", action="store_true", help="Run verification queries after building")
    parser.add_argument("--rebuild", action="store_true", help="Delete and rebuild from scratch")
    args = parser.parse_args()

    print("\n=== Security Guidelines — Knowledge Base Builder ===\n")

    chunks = load_chunks()
    print_domain_summary(chunks)

    ids, documents, metadatas = build_documents(chunks)
    print(f"\nBuilding ChromaDB collection...")
    collection = create_collection(ids, documents, metadatas, rebuild=args.rebuild)

    if args.verify:
        print(f"\nRunning verification queries...\n")
        verify_knowledge_base(collection)

    print("\nKnowledge base ready.\n")


if __name__ == "__main__":
    main()
