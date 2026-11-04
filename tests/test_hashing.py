from pathlib import Path

from reconkit.forensics.hashing import hash_file


def test_hash_file_sha256(tmp_path: Path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"abc")
    assert hash_file(p, algo="sha256") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
