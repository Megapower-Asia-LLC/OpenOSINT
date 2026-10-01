"""Black-box check of the web server's request guard (stdlib only).

Usage: python scripts/ci/check_guard.py http://127.0.0.1:8080 [--restricted true|false] [--fresh]

Always asserts that a request with a foreign Host header and a cross-site POST to
/api/setup are both rejected with 403. With --restricted, also asserts the value of
/api/health's `restricted`; with --fresh, that demo_mode and setup_complete are false
(a fresh install with no keys and no restriction).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

TIMEOUT_SECS = 10


def status_of(url: str, *, method: str = "GET", headers: dict | None = None, body=None) -> int:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECS) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def check_rejections(base: str) -> None:
    code = status_of(f"{base}/api/health", headers={"Host": "evil.example"})
    assert code == 403, f"foreign Host header got {code}, expected 403"
    code = status_of(
        f"{base}/api/setup",
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Origin": "https://evil.example",
            "Sec-Fetch-Site": "cross-site",
        },
        body={},
    )
    assert code == 403, f"cross-site POST /api/setup got {code}, expected 403"
    print(f"ok  guard rejects a foreign Host and a cross-site /api/setup at {base}")


def check_health(base: str, restricted: bool | None, fresh: bool) -> None:
    with urllib.request.urlopen(f"{base}/api/health", timeout=TIMEOUT_SECS) as resp:
        health = json.load(resp)
    if restricted is not None:
        assert health["restricted"] is restricted, f"restricted={health['restricted']}: {health}"
    if fresh:
        assert health["demo_mode"] is False, f"demo_mode is not false: {health}"
        assert health["setup_complete"] is False, f"setup_complete is not false: {health}"
    print(f"ok  health: restricted={health['restricted']} demo_mode={health['demo_mode']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("base")
    parser.add_argument("--restricted", choices=("true", "false"))
    parser.add_argument("--fresh", action="store_true")
    args = parser.parse_args()
    base = args.base.rstrip("/")
    restricted = None if args.restricted is None else args.restricted == "true"
    check_health(base, restricted, args.fresh)
    check_rejections(base)


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        sys.exit(f"FAIL: {exc}")
