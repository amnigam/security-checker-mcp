"""Shared Embedding Function Resolver for ChromaDB.

Priority: ChromaDB ONNX → hash-based fallback.
sentence-transformers has been removed to simplify cross-platform setup.
ChromaDB's built-in ONNX MiniLM gives near-identical quality without
requiring HuggingFace downloads or PyTorch.
"""

import sys


def get_embedding_function(verbose: bool = False):
    """Resolve the best available embedding function for ChromaDB."""

    # ── Try 1: ChromaDB built-in ONNX (good quality, ships with chromadb) ──
    try:
        from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2

        ef = ONNXMiniLM_L6_V2()
        ef(["test"])  # verify it actually loads and runs
        if verbose:
            print("[embeddings] Using ChromaDB ONNX embeddings (all-MiniLM-L6-v2)", file=sys.stderr)
        return ef
    except Exception:
        pass

    # ── Try 2: Hash-based fallback (works everywhere) ────────────
    if verbose:
        print(
            "[embeddings] WARNING: ONNX embeddings not available. "
            "Using hash-based fallback (exact-word matching only).",
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