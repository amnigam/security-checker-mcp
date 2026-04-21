"""Shared Embedding Function Resolver for ChromaDB.

Priority: sentence-transformers → ChromaDB ONNX → hash-based fallback.
Each option is tested before returning to catch missing models or
incompatible runtimes.
"""

import sys


def get_embedding_function(verbose: bool = False):
    """Resolve the best available embedding function for ChromaDB."""

    # ── Try 1: sentence-transformers (best quality) ──────────────
    try:
        from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
        from pathlib import Path

        # Look for model bundled in the repo first, fall back to HuggingFace cache
        _project_root = Path(__file__).resolve().parent.parent.parent
        _local_model = _project_root / "models" / "all-MiniLM-L6-v2"
        model_path = str(_local_model) if _local_model.exists() else "all-MiniLM-L6-v2"

        ef = SentenceTransformerEmbeddingFunction(model_name=model_path)

        # Commented this out to avoid Hugging Face downloading the model. 
        # ef = SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
        ef(["test"])  # verify it actually loads and runs
        if verbose:
            source = "repo-local" if _local_model.exists() else "HuggingFace cache"
            print(f"[embeddings] Using sentence-transformers ({source})", file=sys.stderr)

            # print("[embeddings] Using sentence-transformers (all-MiniLM-L6-v2)", file=sys.stderr)
        return ef
    except Exception:
        pass

    # ── Try 2: ChromaDB built-in ONNX (good quality) ────────────
    try:
        from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2

        ef = ONNXMiniLM_L6_V2()
        ef(["test"])
        if verbose:
            print("[embeddings] Using ChromaDB ONNX embeddings", file=sys.stderr)
        return ef
    except Exception:
        pass

    # ── Try 3: Hash-based fallback (works everywhere) ────────────
    if verbose:
        print(
            "[embeddings] WARNING: No embedding model available. "
            "Using hash-based fallback (exact-word matching only).\n"
            "  For semantic search, install: pip install sentence-transformers",
            file=sys.stderr,
        )

    import hashlib
    import numpy as np
    from chromadb import EmbeddingFunction, Documents, Embeddings

    class HashEmbeddingFunction(EmbeddingFunction):
        """Deterministic hash-based embeddings. Matches exact words only."""

        def __call__(self, input: Documents) -> Embeddings:
            embeddings = []
            for doc in input:
                vec = np.zeros(384, dtype=np.float32)
                for word in doc.lower().split():
                    h = int(hashlib.md5(word.encode()).hexdigest(), 16)
                    vec[h % 384] += 1.0
                norm = np.linalg.norm(vec)
                if norm > 0:
                    vec = vec / norm
                embeddings.append(vec.tolist())
            return embeddings

    return HashEmbeddingFunction()
