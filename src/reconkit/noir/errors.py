from __future__ import annotations


class NoirStackError(Exception):
    """Base class for Noir Stack domain errors."""


class TrustBoundaryError(NoirStackError):
    """Operation attempted across an unapproved or undefined trust boundary."""


class ProvenanceRequiredError(NoirStackError):
    """Raised when an operation requires provenance and none is provided."""


class EvidencePolicyError(NoirStackError):
    """Raised when evidence acquisition violates a declared policy."""


class RobotsDisallowedError(EvidencePolicyError):
    """Raised when robots.txt forbids acquisition for the declared agent."""


class EvidenceSizeLimitError(EvidencePolicyError):
    """Raised when an artifact exceeds declared acquisition limits."""


class AcquisitionFailureError(NoirStackError):
    """Raised when acquisition fails within the declared boundary."""
