from __future__ import annotations

import hashlib
from pathlib import Path


_SUPPORTED = {"md5", "sha1", "sha256"}


def hash_file(path: Path, *, algo: str = "sha256", chunk_size: int = 1024 * 1024) -> str:
    algo = algo.lower()
    if algo not in _SUPPORTED:
        raise ValueError(f"Unsupported algo: {algo}. Choose one of: {sorted(_SUPPORTED)}")

    h = hashlib.new(algo)
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
