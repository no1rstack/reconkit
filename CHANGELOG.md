# Changelog

All notable changes to this project will be documented in this file.

Format: loosely based on *Keep a Changelog*. Versioning: SemVer where practical.

## [0.2.0] - 2026-11-04

### Added
- WARC 1.1 and WACZ 1.2 exports with an index, page list, SHA-256 fixity, and data-package digest.
- Hash-linked chain-of-custody ledgers and Ed25519-signed manifests.
- DFIR-IRIS v2 evidence-registration adapter.
- Redirect-chain recording and conservative public-destination checks for web capture.

### Changed
- Robots rules are checked at every redirect destination and fail closed by default.

## [0.1.0] - 2026-02-09

### Added
- Noir Stack public primitives: `EvidenceArtifact`, `EvidenceBundle`, `ProvenanceRecord`, `VerificationResult`.
- Domain-specific errors that describe trust boundaries and provenance constraints.
- Audit-grade CLI vocabulary: `evidence`, `boundary`, `verify`.
- Structured JSON outputs include: `decision_basis`, `verification_status`, `provenance_confidence`.
- `robots.txt` compliance (default) and rate limiting for web acquisition.

### Changed
- Public-facing surface and CLI terminology refactored to evidence/verification framing.

### Notes
- This release is intentionally conservative.
- The system is capable of refusing to speculate. This is a feature.
