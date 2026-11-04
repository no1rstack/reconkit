"""Ed25519-signed manifests for evidence files."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class ManifestSigner:
    """A local Ed25519 signing key. Keep the private PEM outside evidence exports."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key

    @classmethod
    def generate(cls) -> "ManifestSigner":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, pem: bytes, password: bytes | None = None) -> "ManifestSigner":
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("An Ed25519 private key is required.")
        return cls(key)

    def private_pem(self, password: bytes | None = None) -> bytes:
        encryption = serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(password)
        return self._private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)

    def public_pem(self) -> bytes:
        return self._private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self._private_key.sign(data)).decode("ascii")


def write_manifest(files: list[str | Path], destination: str | Path, signer: ManifestSigner, *, custody_ledger: str | Path | None = None) -> Path:
    items = []
    for item in files:
        path = Path(item)
        contents = path.read_bytes()
        items.append({"path": path.name, "bytes": len(contents), "sha256": hashlib.sha256(contents).hexdigest()})
    manifest: dict[str, Any] = {"version": 1, "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "files": items}
    if custody_ledger is not None:
        ledger = Path(custody_ledger)
        manifest["custody_ledger"] = {"path": ledger.name, "sha256": hashlib.sha256(ledger.read_bytes()).hexdigest()}
    payload = _canonical(manifest)
    envelope = {"manifest": manifest, "algorithm": "Ed25519", "public_key_pem": signer.public_pem().decode("ascii"), "signature": signer.sign(payload)}
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(envelope) + b"\n")
    return path


def verify_manifest(path: str | Path) -> bool:
    envelope = json.loads(Path(path).read_text(encoding="utf-8"))
    public_key = serialization.load_pem_public_key(envelope["public_key_pem"].encode("ascii"))
    if not isinstance(public_key, Ed25519PublicKey) or envelope.get("algorithm") != "Ed25519":
        return False
    try:
        public_key.verify(base64.b64decode(envelope["signature"]), _canonical(envelope["manifest"]))
        return True
    except Exception:
        return False
