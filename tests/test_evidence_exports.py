from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from reconkit.evidence.archives import export_wacz, export_warc
from reconkit.evidence.custody import CustodyLedger
from reconkit.evidence.manifest import ManifestSigner, verify_manifest, write_manifest
from reconkit.scraping.fetch import FetchResult


def capture() -> FetchResult:
    return FetchResult(
        requested_url="https://example.com", url="https://example.com/final", status_code=200,
        headers={"content-type": "text/plain"}, body=b"evidence", encoding="utf-8",
        observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        redirect_chain=({"from": "https://example.com", "to": "https://example.com/final", "status_code": 302},),
    )


def test_warc_and_wacz_include_standard_manifests(tmp_path: Path):
    warc = export_warc([capture()], tmp_path / "capture.warc")
    assert b"WARC/1.1" in warc.read_bytes()
    wacz = export_wacz([capture()], tmp_path / "capture.wacz", title="Test evidence")
    with zipfile.ZipFile(wacz) as archive:
        assert set(archive.namelist()) == {"archive/data.warc", "indexes/index.cdxj", "pages/pages.jsonl", "datapackage.json", "datapackage-digest.json"}
        manifest = json.loads(archive.read("datapackage.json"))
        assert manifest["profile"] == "wacz"
        assert len(manifest["resources"]) == 3


def test_custody_hash_chain_and_signed_manifest_detect_tampering(tmp_path: Path):
    evidence = tmp_path / "capture.warc"
    evidence.write_bytes(b"captured bytes")
    ledger = CustodyLedger(tmp_path / "custody.jsonl")
    ledger.append(action="acquired", actor="analyst@example.test", artifact_path=evidence)
    ledger.append(action="exported", actor="analyst@example.test", artifact_path=evidence)
    assert ledger.verify()
    signer = ManifestSigner.generate()
    manifest = write_manifest([evidence], tmp_path / "manifest.json", signer, custody_ledger=ledger.path)
    assert verify_manifest(manifest)
    assert verify_manifest(manifest, evidence_dir=tmp_path)
    contents = json.loads(manifest.read_text(encoding="utf-8"))
    contents["manifest"]["files"][0]["bytes"] = 1
    manifest.write_text(json.dumps(contents), encoding="utf-8")
    assert not verify_manifest(manifest)
