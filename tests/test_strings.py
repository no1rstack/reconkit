from pathlib import Path

from reconkit.forensics.strings import extract_strings


def test_extract_strings_basic(tmp_path: Path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x00hello\x00world!!!\x00")
    strings = list(extract_strings(p, min_len=5))
    assert "hello" in strings
    assert "world!!!" in strings
