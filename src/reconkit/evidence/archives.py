"""Standards-oriented WARC and WACZ exports for captured HTTP responses."""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from reconkit.scraping.fetch import FetchResult


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _surt(url: str) -> str:
    """Return a CDXJ-compatible SURT key for a captured URL."""
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower().strip(".")
    authority = ",".join(reversed(hostname.split(".")))
    if parsed.port and parsed.port not in {80, 443}:
        authority = f"{authority}:{parsed.port}"
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return f"{authority}){path}"


def _warc_record(headers: dict[str, str], body: bytes) -> bytes:
    head = "WARC/1.1\r\n" + "".join(f"{key}: {value}\r\n" for key, value in headers.items()) + "\r\n"
    return head.encode("utf-8") + body + b"\r\n\r\n"


def _http_response(capture: FetchResult) -> bytes:
    headers = {key: value for key, value in capture.headers.items() if key.lower() not in {"transfer-encoding", "content-length"}}
    headers["Content-Length"] = str(len(capture.body))
    status = f"HTTP/1.1 {capture.status_code}\r\n"
    return status.encode("utf-8") + "".join(f"{key}: {value}\r\n" for key, value in headers.items()).encode("utf-8") + b"\r\n" + capture.body


def warc_bytes(captures: list[FetchResult]) -> tuple[bytes, list[dict[str, object]]]:
    """Create a WARC 1.1 stream and the information needed for a CDXJ index."""
    output = bytearray()
    info = _json({"software": "reconkit", "format": "WARC File Format 1.1"})
    output.extend(_warc_record({
        "WARC-Type": "warcinfo", "WARC-Date": captures[0].observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if captures else "1970-01-01T00:00:00Z",
        "WARC-Record-ID": f"<urn:uuid:{uuid4()}>", "Content-Type": "application/warc-fields", "Content-Length": str(len(info)),
    }, info))
    index: list[dict[str, object]] = []
    for capture in captures:
        offset = len(output)
        payload = _http_response(capture)
        digest = _sha256(payload)
        output.extend(_warc_record({
            "WARC-Type": "response", "WARC-Target-URI": capture.url,
            "WARC-Date": capture.observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "WARC-Record-ID": f"<urn:uuid:{uuid4()}>", "WARC-Block-Digest": f"sha256:{digest}",
            "Content-Type": "application/http; msgtype=response", "Content-Length": str(len(payload)),
        }, payload))
        index.append({"url": capture.url, "timestamp": capture.observed_at.astimezone(timezone.utc).strftime("%Y%m%d%H%M%S"), "status": str(capture.status_code), "digest": f"sha256:{digest}", "offset": offset, "length": len(output) - offset})
    return bytes(output), index


def export_warc(captures: list[FetchResult], destination: str | Path) -> Path:
    """Write a WARC 1.1 file for one or more captures."""
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    data, _ = warc_bytes(captures)
    path.write_bytes(data)
    return path


def export_wacz(captures: list[FetchResult], destination: str | Path, *, title: str = "ReconKit collection") -> Path:
    """Write a WACZ 1.2 archive with WARC, CDXJ, pages, and fixity manifests."""
    if not captures:
        raise ValueError("At least one capture is required for a WACZ export.")
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    warc, index = warc_bytes(captures)
    cdxj = b"".join(
        f"{_surt(str(entry['url']))} {entry['timestamp']} ".encode() + _json({
            "url": entry["url"], "status": entry["status"], "digest": entry["digest"],
            "offset": entry["offset"], "length": entry["length"], "filename": "data.warc",
        }) + b"\n" for entry in index
    )
    pages = b"".join(_json({"url": capture.url, "ts": capture.observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")}) + b"\n" for capture in captures)
    resources = [
        {"name": "data.warc", "path": "archive/data.warc", "hash": f"sha256:{_sha256(warc)}", "bytes": len(warc)},
        {"name": "index.cdxj", "path": "indexes/index.cdxj", "hash": f"sha256:{_sha256(cdxj)}", "bytes": len(cdxj)},
        {"name": "pages.jsonl", "path": "pages/pages.jsonl", "hash": f"sha256:{_sha256(pages)}", "bytes": len(pages)},
    ]
    datapackage = _json({"profile": "wacz", "title": title, "resources": resources})
    digest = _json({"path": "datapackage.json", "hash": f"sha256:{_sha256(datapackage)}"})
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("archive/data.warc", warc)
        archive.writestr("indexes/index.cdxj", cdxj)
        archive.writestr("pages/pages.jsonl", pages)
        archive.writestr("datapackage.json", datapackage)
        archive.writestr("datapackage-digest.json", digest)
    return path
