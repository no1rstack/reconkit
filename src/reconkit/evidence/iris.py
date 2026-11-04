"""Optional DFIR-IRIS v2 evidence registration adapter."""

from __future__ import annotations

import hashlib
from pathlib import Path

import httpx


class DFIRIRISAdapter:
    """Register a preserved file as evidence in an existing DFIR-IRIS case.

    The adapter registers evidence metadata through the documented v2 endpoint.
    Uploading the evidence bytes is intentionally left to the organization's IRIS
    retention workflow.
    """

    def __init__(self, base_url: str, api_key: str, *, timeout: float = 20.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def register(self, case_identifier: int, evidence_path: str | Path, *, description: str = "", type_id: int | None = None) -> dict:
        path = Path(evidence_path)
        payload: dict[str, object] = {
            "filename": path.name, "file_size": path.stat().st_size,
            "file_hash": hashlib.sha256(path.read_bytes()).hexdigest(), "file_description": description,
        }
        if type_id is not None:
            payload["type_id"] = type_id
        response = httpx.post(
            f"{self.base_url}/api/v2/cases/{case_identifier}/evidences", json=payload,
            headers={"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"}, timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()
