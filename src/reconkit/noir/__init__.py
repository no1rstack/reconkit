"""Noir Stack / Hexarch / Judicium public interface.

Deliberately conservative: explicit provenance over convenience.
If you want a tool that invents facts, there are easier ways to do that.
"""

from .errors import (
	AcquisitionFailureError,
	EvidencePolicyError,
	EvidenceSizeLimitError,
	NoirStackError,
	ProvenanceRequiredError,
	RobotsDisallowedError,
	TrustBoundaryError,
)
from .primitives import EvidenceArtifact, EvidenceBundle, ProvenanceRecord, VerificationResult
from .public_api import (
	acquire_web_artifact,
	boundary_dns,
	boundary_ip,
	boundary_whois,
	bundle,
	derive_links,
	derive_readable_text,
	verify_exif,
	verify_file_hash,
	verify_file_type,
	verify_strings,
)

__all__ = [
	"EvidenceArtifact",
	"EvidenceBundle",
	"ProvenanceRecord",
	"VerificationResult",
	"NoirStackError",
	"TrustBoundaryError",
	"ProvenanceRequiredError",
	"EvidencePolicyError",
	"RobotsDisallowedError",
	"EvidenceSizeLimitError",
	"AcquisitionFailureError",
	"acquire_web_artifact",
	"derive_links",
	"derive_readable_text",
	"boundary_dns",
	"boundary_whois",
	"boundary_ip",
	"verify_file_hash",
	"verify_file_type",
	"verify_strings",
	"verify_exif",
	"bundle",
]
