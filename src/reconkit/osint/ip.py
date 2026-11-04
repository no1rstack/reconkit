from __future__ import annotations

from typing import Any

from ipwhois import IPWhois


def lookup(ip: str) -> dict[str, Any]:
    obj = IPWhois(ip)
    data = obj.lookup_rdap(depth=1)

    # Keep a small, stable subset for display
    return {
        "query": ip,
        "asn": data.get("asn"),
        "asn_cidr": data.get("asn_cidr"),
        "asn_country_code": data.get("asn_country_code"),
        "asn_description": data.get("asn_description"),
        "network": {
            "name": (data.get("network") or {}).get("name"),
            "country": (data.get("network") or {}).get("country"),
            "cidr": (data.get("network") or {}).get("cidr"),
        },
        "objects": list((data.get("objects") or {}).keys()),
    }
