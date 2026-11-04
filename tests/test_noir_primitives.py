from reconkit.noir.primitives import EvidenceArtifact, ProvenanceRecord


def test_evidence_artifact_sha256_and_size():
    prov = ProvenanceRecord(
        source="unit-test",
        acquisition_method="synthetic",
        trust_boundary="test-boundary",
    )
    a = EvidenceArtifact.from_bytes(kind="test", payload=b"abc", provenance=prov)
    assert a.size_bytes == 3
    assert a.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
