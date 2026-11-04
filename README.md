# ReconKit

ReconKit is a small Python toolkit for preserving authorized web observations and local file findings as reviewable evidence records. It is a collection layer, not a scanner, case-management system, or source of truth.

It complements reconnaissance tools such as SpiderFoot and BBOT, web archiving tools such as Webrecorder, and case-management platforms such as DFIR-IRIS. ReconKit focuses on the handoff between collection and review: what was collected, where it came from, what redirects occurred, what limits apply, and whether exported files have changed.

## What it provides

- Public-web capture with bounded size, rate limiting, redirect-chain recording, robots checks at every destination, and blocking of private, loopback, and reserved destinations by default.
- Standards-oriented WARC 1.1 and WACZ 1.2 exports. WACZ files contain a WARC, CDXJ index, page list, file-fixity manifest, and data-package digest.
- Append-only, hash-linked chain-of-custody ledgers.
- Ed25519-signed manifests that can be verified offline.
- A DFIR-IRIS v2 adapter that registers an exported evidence file with an existing case.
- Local file hashes, magic-byte identification, EXIF extraction, printable-string extraction, and small DNS/WHOIS/RDAP observations.

## What it does not claim

ReconKit records a transport observation. It does not prove the identity of a publisher, the truth of content, legal chain of custody, or attribution. A SHA-256 digest proves that bytes have not changed relative to the recorded digest; it does not prove where they originated.

Web collection is only for systems and data you own or are authorized to assess. The default public-destination restriction helps prevent accidental collection from local or private infrastructure; it is not a substitute for operational authorization.

## Install

```bash
python -m pip install reconkit
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## Capture and preserve a page

```bash
reconkit evidence archive-warc "https://example.com" --output evidence/example.warc
reconkit evidence archive-wacz "https://example.com" --output evidence/example.wacz --title "Example capture"
```

The WACZ export follows the [WACZ 1.2 layout](https://specs.webrecorder.net/wacz/1.2.0/), so it can be validated and replayed with compatible web-archive tooling.
Robots rules are respected by default; use `--no-obey-robots` only when you have clear authorization for the capture.

## Sign a manifest and record custody

```python
from pathlib import Path
from reconkit.evidence import CustodyLedger, ManifestSigner, verify_manifest, write_manifest

evidence = Path("evidence/example.wacz")
ledger = CustodyLedger("evidence/custody.jsonl")
ledger.append(action="acquired", actor="analyst@example.org", artifact_path=evidence)
ledger.append(action="exported", actor="analyst@example.org", artifact_path=evidence)
assert ledger.verify()

signer = ManifestSigner.generate()
Path("keys/evidence-signing-key.pem").write_bytes(signer.private_pem())
manifest = write_manifest([evidence], "evidence/manifest.json", signer, custody_ledger=ledger.path)
assert verify_manifest(manifest)
```

Keep the private key outside the evidence directory and protect it with your organization’s key-management practices. The manifest embeds the corresponding public key so a reviewer can verify it without the private key.

## Register exported evidence in DFIR-IRIS

```python
from reconkit.evidence import DFIRIRISAdapter

iris = DFIRIRISAdapter("https://iris.example.org", api_key="your-api-key")
iris.register(
    case_identifier=42,
    evidence_path="evidence/example.wacz",
    description="Public web capture; signature and custody ledger stored alongside export.",
)
```

The adapter registers file metadata, digest, and description through DFIR-IRIS’s documented v2 evidence endpoint. Upload and retention of the evidence bytes remain controlled by the case system’s own workflow.

## Existing local commands

```bash
reconkit evidence acquire-web "https://example.com" --trust-boundary public-internet
reconkit evidence derive-links "https://example.com"
reconkit boundary dns example.com
reconkit verify file-hash .\sample.bin --algo sha256
```

## Development

```bash
pytest
python -m build
twine check dist/*
```

## Releases

PyPI publication is automated by GitHub Actions. After updating the version in
`pyproject.toml` and the changelog, push the matching annotated tag (for example,
`v0.3.0`). The workflow verifies that the tag and package version match, builds
the distributions, validates them with Twine, and publishes using the repository's
`PYPI_API_TOKEN` Actions secret. Ordinary branch pushes never publish a release.

## License

Copyright © 2026 Noir Stack LLC. Licensed under the
[Proprietary Software License — Free Use, No Modification](LICENSE).
