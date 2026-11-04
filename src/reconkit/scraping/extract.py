from __future__ import annotations

from urllib.parse import urljoin

from bs4 import BeautifulSoup


def extract_links(html: bytes, *, base_url: str) -> list[str]:
    soup = BeautifulSoup(html, "lxml")
    out: list[str] = []
    for a in soup.select("a[href]"):
        href = a.get("href")
        if not href or not isinstance(href, str):
            continue
        out.append(urljoin(base_url, href))
    # de-dup while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for u in out:
        if u in seen:
            continue
        seen.add(u)
        unique.append(u)
    return unique


def readable_text(html: bytes, *, base_url: str | None = None) -> str:
    soup = BeautifulSoup(html, "lxml")

    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = soup.get_text("\n")
    lines = [line.strip() for line in text.splitlines()]
    lines = [line for line in lines if line]
    return "\n".join(lines)
