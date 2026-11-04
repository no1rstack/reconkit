import json
from pathlib import Path

from typer.testing import CliRunner

from reconkit.cli import app


def test_verify_file_hash_emits_required_fields(tmp_path: Path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"abc")

    runner = CliRunner()
    result = runner.invoke(app, ["verify", "file-hash", str(p), "--algo", "sha256"])
    assert result.exit_code == 0, result.stdout

    data = json.loads(result.stdout)
    assert "decision_basis" in data
    assert "verification_status" in data
    assert "provenance_confidence" in data

    assert data["verification_status"] == "informational"
    assert data["findings"]["digest"].startswith("ba7816bf")
