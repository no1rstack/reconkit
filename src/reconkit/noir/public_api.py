from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from reconkit.forensics import exif as exif_mod
from reconkit.forensics import hashing, identify, strings as strings_mod
from reconkit.osint import dns as dns_mod
from reconkit.osint import ip as ip_mod
from reconkit.osint import whois as whois_mod
from reconkit.scraping import extract, fetch

from .errors import NoirStackError
from .primitives import EvidenceArtifact, EvidenceBundle, ProvenanceRecord, VerificationResult


def acquire_web_artifact(
    url: str,
    *,
    trust_boundary: str = "public-internet",
    rps: float = 1.0,
    timeout_s: float = 20.0,
    max_bytes: int = 2_000_000,
    obey_robots: bool = True,
    user_agent: str = "reconkit/0.1 (+https://localhost)",
) -> EvidenceArtifact:
    """Acquire a web artifact as evidence.

    Conservatism note: this only asserts transport-level acquisition. It does not assert truth.
    """

    prov = ProvenanceRecord(
        source=url,
        acquisition_method="http-get",
        trust_boundary=trust_boundary,
        notes=[
            "Transport acquisition only; content authenticity is not asserted.",
        ],
    )

    try:
        result = fetch.fetch_url(
            url,
            max_bytes=max_bytes,
            timeout_s=timeout_s,
            rps=rps,
            obey_robots=obey_robots,
            user_agent=user_agent,
        )
    except NoirStackError:
        raise

    media_type = result.headers.get("content-type")
    return EvidenceArtifact.from_bytes(
        kind="web-response",
        payload=result.body,
        media_type=media_type,
        encoding=result.encoding,
        provenance=ProvenanceRecord(
            source=result.url, acquisition_method="http-get", trust_boundary=trust_boundary,
            observed_at=result.observed_at,
            notes=prov.notes + [f"redirect_chain={list(result.redirect_chain)!r}"],
        ),
    )


def derive_links(artifact: EvidenceArtifact, *, base_url: str) -> EvidenceArtifact:
    links = extract.extract_links(artifact.payload, base_url=base_url)
    payload = ("\n".join(links) + "\n").encode("utf-8")
    prov = ProvenanceRecord(
        source=artifact.artifact_id,
        acquisition_method="derived-links",
        trust_boundary=artifact.provenance.trust_boundary,
        notes=[
            "Derived artifact; link extraction is heuristic and HTML-dependent.",
        ],
    )
    return EvidenceArtifact.from_bytes(
        kind="derived-links",
        payload=payload,
        media_type="text/plain",
        encoding="utf-8",
        provenance=prov,
    )


def derive_readable_text(artifact: EvidenceArtifact, *, base_url: str) -> EvidenceArtifact:
    text = extract.readable_text(artifact.payload, base_url=base_url)
    payload = (text + "\n").encode("utf-8")
    prov = ProvenanceRecord(
        source=artifact.artifact_id,
        acquisition_method="derived-readable-text",
        trust_boundary=artifact.provenance.trust_boundary,
        notes=[
            "Derived artifact; readability extraction removes scripts/styles and may omit context.",
        ],
    )
    return EvidenceArtifact.from_bytes(
        kind="derived-readable-text",
        payload=payload,
        media_type="text/plain",
        encoding="utf-8",
        provenance=prov,
    )


def boundary_dns(domain: str) -> EvidenceArtifact:
    data = dns_mod.lookup(domain)
    prov = ProvenanceRecord(
        source=domain,
        acquisition_method="dns-resolve",
        trust_boundary="public-internet",
        notes=[
            "DNS answers are boundary observations, not identity proofs.",
        ],
    )
    payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
    return EvidenceArtifact.from_bytes(
        kind="boundary-dns",
        payload=payload,
        media_type="application/json",
        encoding="utf-8",
        provenance=prov,
    )


def boundary_whois(domain: str) -> EvidenceArtifact:
    data = whois_mod.lookup(domain)
    prov = ProvenanceRecord(
        source=domain,
        acquisition_method="whois",
        trust_boundary="public-internet",
        notes=[
            "WHOIS data is registrar-provided and may be redacted or stale.",
        ],
    )
    payload = json.dumps(data, indent=2, sort_keys=True, default=str).encode("utf-8")
    return EvidenceArtifact.from_bytes(
        kind="boundary-whois",
        payload=payload,
        media_type="application/json",
        encoding="utf-8",
        provenance=prov,
    )


def boundary_ip(ip: str) -> EvidenceArtifact:
    data = ip_mod.lookup(ip)
    prov = ProvenanceRecord(
        source=ip,
        acquisition_method="ip-whois-rdap",
        trust_boundary="public-internet",
        notes=[
            "RDAP/WHOIS is administrative metadata; attribution remains a separate claim.",
        ],
    )
    payload = json.dumps(data, indent=2, sort_keys=True, default=str).encode("utf-8")
    return EvidenceArtifact.from_bytes(
        kind="boundary-ip",
        payload=payload,
        media_type="application/json",
        encoding="utf-8",
        provenance=prov,
    )


def verify_file_hash(path: Path, *, algo: str = "sha256") -> VerificationResult:
    digest = hashing.hash_file(path, algo=algo)
    return VerificationResult(
        verification_status="informational",
        decision_basis=f"computed {algo} over file bytes",
        provenance_confidence="high",
        subject={"path": str(path), "algo": algo},
        findings={"digest": digest},
        limitations=[
            "Hash computation verifies byte stability, not file origin.",
        ],
    )


def verify_file_type(path: Path) -> VerificationResult:
    info = identify.identify_file(path)
    return VerificationResult(
        verification_status="informational",
        decision_basis="magic-byte signature guess",
        provenance_confidence="high",
        subject={"path": str(path)},
        findings=info,
        limitations=[
            "File type guess is heuristic; containers and polyglots may evade identification.",
        ],
    )


def verify_exif(path: Path) -> VerificationResult:
    data = exif_mod.extract_exif(path)
    return VerificationResult(
        verification_status="informational",
        decision_basis="EXIF tag extraction",
        provenance_confidence="high",
        subject={"path": str(path)},
        findings={"exif": data},
        limitations=[
            "EXIF may be absent, altered, or stripped; authenticity is not asserted.",
        ],
    )


def verify_strings(path: Path, *, min_len: int = 6, max_strings: Optional[int] = None) -> VerificationResult:
    strings = list(strings_mod.extract_strings(path, min_len=min_len, max_strings=max_strings))
    return VerificationResult(
        verification_status="informational",
        decision_basis=f"ASCII printable strings, min_len={min_len}",
        provenance_confidence="high",
        subject={"path": str(path), "min_len": min_len, "max_strings": max_strings},
        findings={"strings": strings},
        limitations=[
            "This extractor is ASCII-only and will miss many encodings.",
        ],
    )


def bundle(*artifacts: EvidenceArtifact, notes: Optional[list[str]] = None) -> EvidenceBundle:
    return EvidenceBundle.of(*artifacts, notes=notes)
