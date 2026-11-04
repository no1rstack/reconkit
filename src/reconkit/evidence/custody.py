"""Append-only, hash-linked chain-of-custody ledgers."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class CustodyLedger:
    """A JSONL ledger whose event hash commits to the previous event hash."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def append(self, *, action: str, actor: str, artifact_path: str | Path, notes: str = "") -> dict[str, Any]:
        artifact = Path(artifact_path)
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        previous = self._last_hash()
        event = {
            "event_id": str(uuid4()), "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "action": action, "actor": actor, "artifact": {"path": artifact.name, "sha256": digest, "bytes": artifact.stat().st_size},
            "notes": notes, "previous_event_sha256": previous,
        }
        event["event_sha256"] = hashlib.sha256(_canonical(event)).hexdigest()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(_canonical(event).decode("utf-8") + "\n")
        return event

    def verify(self) -> bool:
        previous: str | None = None
        if not self.path.exists():
            return True
        for line in self.path.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            claimed = event.pop("event_sha256", None)
            if claimed != hashlib.sha256(_canonical(event)).hexdigest() or event.get("previous_event_sha256") != previous:
                return False
            previous = claimed
        return True

    def _last_hash(self) -> str | None:
        if not self.path.exists() or not self.path.stat().st_size:
            return None
        return json.loads(self.path.read_text(encoding="utf-8").splitlines()[-1])["event_sha256"]
