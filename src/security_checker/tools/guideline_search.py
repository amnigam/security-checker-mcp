"""GuidelineSearch — semantic RAG search over the ChromaDB knowledge base.

Accepts a natural language query, optional domain and language filters,
and returns the top-k matching guideline chunks with IDs, full text,
and relevance scores.
"""

from pathlib import Path
import chromadb
from security_checker.embedding_utils import get_embedding_function

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_PERSIST_DIR = _PROJECT_ROOT / "knowledge" / "chroma_store"
_COLLECTION_NAME = "security_guidelines"
_DEFAULT_TOP_K = 5

# Module-level cache for the collection
_collection = None


def _get_collection() -> chromadb.Collection:
    """Lazily initialize and cache the ChromaDB collection."""
    global _collection
    if _collection is None:
        embedding_fn = get_embedding_function(verbose=False)
        client = chromadb.PersistentClient(path=str(_PERSIST_DIR))
        _collection = client.get_collection(
            _COLLECTION_NAME, embedding_function=embedding_fn
        )
    return _collection


def search_guidelines_db(
    query: str,
    domain_code: str = "",
    language: str = "",
    top_k: int = 0,
) -> str:
    """Search the security guidelines knowledge base.

    Args:
        query: Natural language search query.
        domain_code: Optional domain filter (SM, AU, AZ, IV, etc.).
        language: Optional language filter (python, javascript, etc.).
        top_k: Number of results (default 5).

    Returns:
        Formatted text with matching guidelines.
    """
    collection = _get_collection()
    n_results = top_k if top_k > 0 else _DEFAULT_TOP_K

    # Append language to query for better semantic matching
    search_query = f"{query} {language.lower()}" if language else query

    # Use domain_code as metadata filter (exact match)
    where_filter = {"domain_code": domain_code.upper()} if domain_code else None

    try:
        results = collection.query(
            query_texts=[search_query],
            n_results=min(n_results, 20),
            where=where_filter,
        )
    except Exception as e:
        return f"Error querying knowledge base: {str(e)}"

    if not results["ids"] or not results["ids"][0]:
        return f"No guidelines found for query: '{query}'. Try a broader query or remove filters."

    output_parts = []
    ids = results["ids"][0]
    metadatas = results["metadatas"][0]
    distances = results["distances"][0] if results.get("distances") else [None] * len(ids)

    for i, (gid, meta, dist) in enumerate(zip(ids, metadatas, distances), 1):
        relevance = f" (relevance: {1 - dist:.2f})" if dist is not None else ""
        output_parts.append(
            f"--- Guideline {i}{relevance} ---\n"
            f"ID: {gid}\n"
            f"Domain: {meta['domain']} ({meta['domain_code']})\n"
            f"Section: {meta['parent_code']} — {meta['parent_title']}\n"
            f"Severity: {meta['severity']}\n"
            f"Requirement: {meta['raw_text']}\n"
        )

    header = f"Found {len(ids)} relevant guidelines"
    if domain_code:
        header += f" in domain {domain_code.upper()}"
    if language:
        header += f" for {language}"
    header += ":\n\n"

    return header + "\n".join(output_parts)
