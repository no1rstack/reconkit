from __future__ import annotations

import dns.resolver


def lookup(domain: str) -> dict[str, list[str]]:
    resolver = dns.resolver.Resolver()
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
    result: dict[str, list[str]] = {}

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            result[rtype] = [str(a).strip() for a in answers]
        except Exception:
            result[rtype] = []

    return result
