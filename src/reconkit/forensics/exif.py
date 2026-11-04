from __future__ import annotations

from pathlib import Path

import exifread


def extract_exif(path: Path) -> dict[str, str]:
    with path.open("rb") as f:
        tags = exifread.process_file(f, details=False)

    # normalize to plain strings
    out: dict[str, str] = {}
    for k, v in tags.items():
        out[str(k)] = str(v)
    return out
