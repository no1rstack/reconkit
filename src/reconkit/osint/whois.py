from __future__ import annotations

from typing import Any

import whois


def lookup(domain: str) -> dict[str, Any]:
    """Perform a WHOIS lookup and normalize to a JSON-friendly dict."""

    w = whois.whois(domain)
    # python-whois returns a dict-like object with some date fields.
    data: dict[str, Any] = dict(w)
    return data
