from __future__ import annotations

from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx

_CACHE: dict[str, RobotFileParser] = {}


def robots_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}/robots.txt"


def can_fetch(
    url: str,
    *,
    user_agent: str,
    timeout_s: float = 10.0,
    client: httpx.Client | None = None,
    fail_closed: bool = True,
) -> bool:
    """Return whether `user_agent` is allowed to fetch `url` per robots.txt.

    When ``fail_closed`` is true, an unavailable or malformed robots.txt denies
    collection. That is the conservative default for evidence collection.
    """

    parsed = urlparse(url)
    key = f"{parsed.scheme}://{parsed.netloc}"
    rp = _CACHE.get(key)
    if rp is None:
        rp = RobotFileParser()
        robots_txt = f"{key}/robots.txt"
        rp.set_url(robots_txt)

        try:
            if client is None:
                with httpx.Client(timeout=httpx.Timeout(timeout_s), follow_redirects=True) as c:
                    resp = c.get(robots_txt)
            else:
                resp = client.get(robots_txt)

            if resp.status_code >= 400:
                _CACHE[key] = rp
                return not fail_closed

            rp.parse(resp.text.splitlines())
        except Exception:
            _CACHE[key] = rp
            return not fail_closed

        _CACHE[key] = rp

    try:
        return bool(rp.can_fetch(user_agent, url))
    except Exception:
        return not fail_closed
