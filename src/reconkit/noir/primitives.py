from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Optional
from uuid import uuid4

VerificationStatus = Literal[
    "verified",
    "unverified",
    "inconclusive",
    "blocked",
    "informational",
]

ProvenanceConfidence = Literal[
    "high",
    "medium",
    "low",
    "unknown",
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ProvenanceRecord:
    """Audit-grade statement of how an artifact was obtained.

    This is not a promise of truth. It is a statement of method, boundary, and limits.
    """

    source: str
    acquisition_method: str
    trust_boundary: str
    observed_at: datetime = field(default_factory=_utc_now)
    observer: str = "reconkit.judicium"
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EvidenceArtifact:
    """Opaque artifact plus provenance.

    Treat payload as immutable evidence; derive additional artifacts rather than mutating.
    """

    artifact_id: str
    kind: str
    payload: bytes
    media_type: Optional[str]
    encoding: Optional[str]
    provenance: ProvenanceRecord
    sha256: str
    size_bytes: int

    @staticmethod
    def from_bytes(
        *,
        kind: str,
        payload: bytes,
        provenance: ProvenanceRecord,
        media_type: Optional[str] = None,
        encoding: Optional[str] = None,
        artifact_id: Optional[str] = None,
    ) -> "EvidenceArtifact":
        digest = hashlib.sha256(payload).hexdigest()
        return EvidenceArtifact(
            artifact_id=artifact_id or str(uuid4()),
            kind=kind,
            payload=payload,
            media_type=media_type,
            encoding=encoding,
            provenance=provenance,
            sha256=digest,
            size_bytes=len(payload),
        )

    def to_json_dict(self, *, include_payload: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "encoding": self.encoding,
            "provenance": {
                "source": self.provenance.source,
                "acquisition_method": self.provenance.acquisition_method,
                "trust_boundary": self.provenance.trust_boundary,
                "observed_at": self.provenance.observed_at.isoformat(),
                "observer": self.provenance.observer,
                "notes": list(self.provenance.notes),
            },
        }
        if include_payload:
            out["payload_b64"] = base64.b64encode(self.payload).decode("ascii")
        return out


@dataclass(frozen=True)
class EvidenceBundle:
    """A set of artifacts intended to be assessed together."""

    bundle_id: str
    artifacts: list[EvidenceArtifact]
    created_at: datetime = field(default_factory=_utc_now)
    notes: list[str] = field(default_factory=list)

    @staticmethod
    def of(*artifacts: EvidenceArtifact, notes: Optional[list[str]] = None) -> "EvidenceBundle":
        return EvidenceBundle(
            bundle_id=str(uuid4()),
            artifacts=list(artifacts),
            notes=list(notes or []),
        )


@dataclass(frozen=True)
class VerificationResult:
    """Result of a verification action.

    Required fields for structured output:
    - decision_basis
    - verification_status
    - provenance_confidence
    """

    verification_status: VerificationStatus
    decision_basis: str
    provenance_confidence: ProvenanceConfidence

    subject: dict[str, Any] = field(default_factory=dict)
    findings: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "verification_status": self.verification_status,
            "decision_basis": self.decision_basis,
            "provenance_confidence": self.provenance_confidence,
            "subject": self.subject,
            "findings": self.findings,
            "limitations": list(self.limitations),
        }


def json_dumps_audit(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, default=str)
