from __future__ import annotations

from pathlib import Path

import filetype


def identify_file(path: Path) -> dict[str, str | None]:
    kind = filetype.guess(str(path))
    if kind is None:
        return {"path": str(path), "ext": None, "mime": None}
    return {"path": str(path), "ext": kind.extension, "mime": kind.mime}
