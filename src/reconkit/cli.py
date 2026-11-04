from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from reconkit.evidence.archives import export_wacz, export_warc
from reconkit.noir import public_api
from reconkit.noir.primitives import VerificationResult, json_dumps_audit
from reconkit.scraping.fetch import fetch_url

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()

evidence_app = typer.Typer(no_args_is_help=True)
boundary_app = typer.Typer(no_args_is_help=True)
verify_app = typer.Typer(no_args_is_help=True)
app.add_typer(evidence_app, name="evidence")
app.add_typer(boundary_app, name="boundary")
app.add_typer(verify_app, name="verify")


def _emit(result: VerificationResult) -> None:
    # Audit-grade requirement: stdout must be machine-parseable JSON.
    # Rich is excellent at presentation and equally excellent at line-wrapping.
    # We only need one of those properties.
    typer.echo(json_dumps_audit(result.to_json_dict()))


@evidence_app.command("acquire-web")
def evidence_acquire_web(
    url: str,
    trust_boundary: str = typer.Option(
        "public-internet",
        help="Declared trust boundary for acquisition (audited, not inferred).",
    ),
    max_bytes: int = typer.Option(2_000_000, help="Max download size in bytes"),
    timeout_s: float = typer.Option(20.0, help="Timeout in seconds"),
    rps: float = typer.Option(1.0, help="Max requests per second"),
    obey_robots: bool = typer.Option(True, help="Respect robots.txt"),
    include_payload: bool = typer.Option(False, help="Include payload in output (base64)."),
):
    """Acquire a web response as evidence.

    Conservative note: this is acquisition, not authentication. The system is many things.
    Omniscient is not currently one of them.
    """

    artifact = public_api.acquire_web_artifact(
        url,
        trust_boundary=trust_boundary,
        max_bytes=max_bytes,
        timeout_s=timeout_s,
        rps=rps,
        obey_robots=obey_robots,
    )
    _emit(
        VerificationResult(
            verification_status="informational",
            decision_basis="http-get acquisition within declared trust boundary",
            provenance_confidence="medium",
            subject={"url": url, "trust_boundary": trust_boundary},
            findings={"artifact": artifact.to_json_dict(include_payload=include_payload)},
            limitations=[
                "Transport acquisition does not assert publisher identity or content authenticity.",
            ],
        )
    )


@evidence_app.command("archive-warc")
def evidence_archive_warc(
    url: str,
    output: Path = typer.Option(..., "--output", "-o"),
    max_bytes: int = typer.Option(2_000_000),
):
    """Capture one public URL and preserve its response in WARC 1.1."""
    capture = fetch_url(url, max_bytes=max_bytes)
    path = export_warc([capture], output)
    typer.echo(json_dumps_audit({"format": "WARC 1.1", "path": str(path)}))


@evidence_app.command("archive-wacz")
def evidence_archive_wacz(
    url: str,
    output: Path = typer.Option(..., "--output", "-o"),
    title: str = typer.Option("ReconKit collection"),
    max_bytes: int = typer.Option(2_000_000),
):
    """Capture one public URL and create a portable WACZ 1.2 archive."""
    capture = fetch_url(url, max_bytes=max_bytes)
    path = export_wacz([capture], output, title=title)
    typer.echo(json_dumps_audit({"format": "WACZ 1.2", "path": str(path)}))


@evidence_app.command("derive-links")
def evidence_derive_links(
    url: str,
    timeout_s: float = typer.Option(20.0, help="Timeout in seconds"),
    rps: float = typer.Option(1.0, help="Max requests per second"),
    obey_robots: bool = typer.Option(True, help="Respect robots.txt"),
    include_payload: bool = typer.Option(False, help="Include payload in output (base64)."),
):
    """Acquire a web response and derive a link-list artifact."""

    web = public_api.acquire_web_artifact(url, timeout_s=timeout_s, rps=rps, obey_robots=obey_robots)
    derived = public_api.derive_links(web, base_url=url)
    _emit(
        VerificationResult(
            verification_status="informational",
            decision_basis="derived link extraction from acquired HTML",
            provenance_confidence="medium",
            subject={"url": url},
            findings={
                "source_artifact": web.to_json_dict(include_payload=False),
                "derived_artifact": derived.to_json_dict(include_payload=include_payload),
            },
            limitations=[
                "Link extraction is heuristic and may miss dynamically generated URLs.",
            ],
        )
    )


@evidence_app.command("derive-text")
def evidence_derive_text(
    url: str,
    timeout_s: float = typer.Option(20.0, help="Timeout in seconds"),
    rps: float = typer.Option(1.0, help="Max requests per second"),
    obey_robots: bool = typer.Option(True, help="Respect robots.txt"),
    include_payload: bool = typer.Option(False, help="Include payload in output (base64)."),
):
    """Acquire a web response and derive a readable-text artifact."""

    web = public_api.acquire_web_artifact(url, timeout_s=timeout_s, rps=rps, obey_robots=obey_robots)
    derived = public_api.derive_readable_text(web, base_url=url)
    _emit(
        VerificationResult(
            verification_status="informational",
            decision_basis="derived readable text from acquired HTML",
            provenance_confidence="medium",
            subject={"url": url},
            findings={
                "source_artifact": web.to_json_dict(include_payload=False),
                "derived_artifact": derived.to_json_dict(include_payload=include_payload),
            },
            limitations=[
                "Readability extraction removes scripts/styles and may omit critical context.",
            ],
        )
    )


@boundary_app.command("dns")
def boundary_dns(domain: str, include_payload: bool = typer.Option(False, help="Include payload in output (base64).")):
    """Observe DNS answers across the public-internet boundary."""

    artifact = public_api.boundary_dns(domain)
    _emit(
        VerificationResult(
            verification_status="informational",
            decision_basis="DNS resolution observation",
            provenance_confidence="medium",
            subject={"domain": domain, "trust_boundary": "public-internet"},
            findings={"artifact": artifact.to_json_dict(include_payload=include_payload)},
            limitations=[
                "DNS is an administrative naming system; answers are not identity proofs.",
            ],
        )
    )


@boundary_app.command("whois")
def boundary_whois(domain: str, include_payload: bool = typer.Option(False, help="Include payload in output (base64).")):
    """Observe WHOIS/RDAP administrative metadata across the public-internet boundary."""

    artifact = public_api.boundary_whois(domain)
    _emit(
        VerificationResult(
            verification_status="informational",
            decision_basis="WHOIS observation",
            provenance_confidence="low",
            subject={"domain": domain, "trust_boundary": "public-internet"},
            findings={"artifact": artifact.to_json_dict(include_payload=include_payload)},
            limitations=[
                "WHOIS fields vary by registrar/TLD and may be redacted or stale.",
            ],
        )
    )


@boundary_app.command("ip")
def boundary_ip(ip: str, include_payload: bool = typer.Option(False, help="Include payload in output (base64).")):
    """Observe RDAP/ASN administrative metadata across the public-internet boundary."""

    artifact = public_api.boundary_ip(ip)
    _emit(
        VerificationResult(
            verification_status="informational",
            decision_basis="RDAP/ASN observation",
            provenance_confidence="medium",
            subject={"ip": ip, "trust_boundary": "public-internet"},
            findings={"artifact": artifact.to_json_dict(include_payload=include_payload)},
            limitations=[
                "Administrative allocations do not imply actor attribution.",
            ],
        )
    )


@verify_app.command("file-hash")
def verify_file_hash(
    path: Path,
    algo: str = typer.Option("sha256", help="md5|sha1|sha256"),
):
    """Verify (informational): compute a cryptographic digest over file bytes."""

    _emit(public_api.verify_file_hash(path, algo=algo))


@verify_app.command("file-type")
def verify_file_type(path: Path):
    """Verify (informational): identify file type by signature."""

    _emit(public_api.verify_file_type(path))


@verify_app.command("strings")
def verify_strings(
    path: Path,
    min_len: int = typer.Option(6, "--min-len"),
    max_strings: Optional[int] = typer.Option(None, "--max"),
):
    """Verify (informational): extract printable strings as a triage aid."""

    _emit(public_api.verify_strings(path, min_len=min_len, max_strings=max_strings))


@verify_app.command("exif")
def verify_exif(path: Path):
    """Verify (informational): extract EXIF tags."""

    _emit(public_api.verify_exif(path))
