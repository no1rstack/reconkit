from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import socket
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from reconkit.core.rate_limit import RateLimiter
from reconkit.scraping import robots
from reconkit.noir.errors import AcquisitionFailureError, EvidenceSizeLimitError, RobotsDisallowedError


@dataclass
class FetchResult:
    requested_url: str
    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    encoding: Optional[str]
    observed_at: datetime
    redirect_chain: tuple[dict[str, object], ...] = ()


def _validate_url(url: str, *, allow_private_hosts: bool) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise AcquisitionFailureError("Only absolute, credential-free http(s) URLs are permitted.")
    if allow_private_hosts:
        return
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, None)}
    except OSError as exc:
        raise AcquisitionFailureError(f"Could not resolve destination host: {parsed.hostname}") from exc
    for address in addresses:
        value = ipaddress.ip_address(address)
        if not value.is_global:
            raise AcquisitionFailureError("Private, loopback, link-local, and reserved destinations are blocked by default.")


def fetch_url(
    url: str,
    *,
    max_bytes: int = 2_000_000,
    timeout_s: float = 20.0,
    rps: float = 1.0,
    obey_robots: bool = True,
    user_agent: str = "reconkit/0.2 (+https://github.com/no1rstack/reconkit)",
    retries: int = 2,
    max_redirects: int = 10,
    allow_private_hosts: bool = False,
    robots_fail_closed: bool = True,
) -> FetchResult:
    """Fetch a URL with conservative defaults.

    No anti-bot bypass behavior is implemented (no proxy rotation, no fingerprinting evasion).
    """

    _validate_url(url, allow_private_hosts=allow_private_hosts)
    limiter = RateLimiter(requests_per_second=rps)

    headers = {"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
    timeout = httpx.Timeout(timeout_s)

    redirects: list[dict[str, object]] = []
    current_url = url
    with httpx.Client(follow_redirects=False, timeout=timeout, headers=headers) as client:
        for _ in range(max_redirects + 1):
            _validate_url(current_url, allow_private_hosts=allow_private_hosts)
            limiter.wait()
            if obey_robots and not robots.can_fetch(
                current_url, user_agent=user_agent, timeout_s=min(10.0, timeout_s), client=client,
                fail_closed=robots_fail_closed,
            ):
                raise RobotsDisallowedError("Acquisition denied because robots.txt does not authorize this URL.")
            for attempt in range(retries + 1):
                try:
                    with client.stream("GET", current_url) as resp:
                        location = resp.headers.get("location")
                        if resp.status_code in {301, 302, 303, 307, 308} and location:
                            next_url = urljoin(current_url, location)
                            redirects.append({"from": current_url, "to": next_url, "status_code": resp.status_code})
                            current_url = next_url
                            break
                        if resp.status_code >= 400:
                            raise AcquisitionFailureError(f"Collection failed with HTTP status {resp.status_code}.")
                        chunks: list[bytes] = []
                        size = 0
                        for chunk in resp.iter_bytes():
                            size += len(chunk)
                            if max_bytes and size > max_bytes:
                                raise EvidenceSizeLimitError(f"Evidence size limit exceeded (max_bytes={max_bytes}).")
                            chunks.append(chunk)
                        return FetchResult(
                            requested_url=url, url=str(resp.url), status_code=resp.status_code,
                            headers={k: v for k, v in resp.headers.items()}, body=b"".join(chunks),
                            encoding=resp.encoding, observed_at=datetime.now(timezone.utc),
                            redirect_chain=tuple(redirects),
                        )
                except AcquisitionFailureError:
                    raise
                except (httpx.TimeoutException, httpx.NetworkError) as exc:
                    if attempt >= retries:
                        raise AcquisitionFailureError("Collection failed because the destination was unavailable.") from exc
            else:
                raise AcquisitionFailureError("Collection retry loop ended unexpectedly.")
            continue
    raise AcquisitionFailureError(f"Redirect limit exceeded ({max_redirects}).")
