from __future__ import annotations

from pathlib import Path
from typing import Iterator, Optional


_PRINTABLE = set(range(0x20, 0x7F))  # basic ASCII printable


def extract_strings(
    path: Path,
    *,
    min_len: int = 6,
    max_strings: Optional[int] = None,
    chunk_size: int = 1024 * 1024,
) -> Iterator[str]:
    """Extract basic ASCII printable strings.

    Intentionally simple (easy to replicate). For deeper analysis, consider specialized tools.
    """

    buf = bytearray()
    yielded = 0

    def flush() -> Iterator[str]:
        nonlocal buf, yielded
        if len(buf) >= min_len:
            yielded += 1
            yield buf.decode("ascii", errors="ignore")
        buf = bytearray()

    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            for b in chunk:
                if b in _PRINTABLE:
                    buf.append(b)
                else:
                    for s in flush():
                        yield s
                        if max_strings is not None and yielded >= max_strings:
                            return

    for s in flush():
        yield s
