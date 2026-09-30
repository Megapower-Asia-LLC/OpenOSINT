"""Clean-environment smoke test for the one-command install (stdlib only).

Runs `uvx --from <wheel> openosint web` exactly as a new user would, but with
every key/config variable stripped and HOME/USERPROFILE/APPDATA pointed at an
empty temp directory, from an empty working directory. It then checks that:

  1. the web UI answers (/api/health and /) and prints its real URL,
  2. a second instance on the same port fails with a message naming --port,
  3. `openosint-mcp` starts, reports the wheel's version and lists the tools.

Usage: python scripts/ci/smoke_install.py dist/openosint-X.Y.Z-py3-none-any.whl [--extra graph]
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

START_TIMEOUT_SECS = 300  # first run downloads and installs every dependency
FAIL_FAST_TIMEOUT_SECS = 120
MIN_TOOLS = 20
SECRET_MARKERS = (
    "KEY", "TOKEN", "SECRET", "PASSWORD", "OPENOSINT", "ANTHROPIC", "OPENAI",
    "OLLAMA", "SHODAN", "CENSYS", "VIRUSTOTAL", "IPINFO", "HIBP", "BRIGHTDATA",
)  # fmt: skip


def _uv_dir(*args: str) -> str:
    return subprocess.run(["uv", *args], capture_output=True, text=True, check=True).stdout.strip()


def clean_env(home: Path) -> dict[str, str]:
    """Current env minus anything key-like, with all home/config dirs isolated."""
    env = {
        k: v for k, v in os.environ.items() if not any(m in k.upper() for m in SECRET_MARKERS)
    }
    # Keep uv's own cache/python store so the run stays fast; everything the
    # app itself might read or write is redirected below.
    env["UV_CACHE_DIR"] = _uv_dir("cache", "dir")
    env["UV_PYTHON_INSTALL_DIR"] = _uv_dir("python", "dir")
    for var in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
        env[var] = str(home)
    env["PYTHONUNBUFFERED"] = "1"
    return env


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def fetch(url: str) -> tuple[int, str]:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def stop(proc: subprocess.Popen) -> None:
    """Terminate uvx and the tool process it spawned."""
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
    else:
        os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()


def spawn(cmd: list[str], env: dict, cwd: Path, log: Path) -> subprocess.Popen:
    kwargs = {"start_new_session": True} if os.name != "nt" else {}
    with log.open("w") as out:
        return subprocess.Popen(
            cmd, env=env, cwd=cwd, stdout=out, stderr=subprocess.STDOUT, **kwargs
        )


def wait_for_health(url: str, proc: subprocess.Popen, log: Path) -> None:
    deadline = time.monotonic() + START_TIMEOUT_SECS
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"web server exited early (code {proc.returncode}):\n{log.read_text()}")
        try:
            status, body = fetch(f"{url}/api/health")
            if status == 200 and json.loads(body).get("status") == "ok":
                return
        except OSError:
            pass
        time.sleep(1)
    raise SystemExit(f"web server not healthy after {START_TIMEOUT_SECS}s:\n{log.read_text()}")


def check_web(runner: list[str], env: dict, work: Path) -> None:
    port = free_port()
    url = f"http://127.0.0.1:{port}"
    cmd = [*runner, "openosint", "web", "--no-browser", "--port", str(port)]
    first = spawn(cmd, env, work, work / "web.log")
    try:
        wait_for_health(url, first, work / "web.log")
        status, body = fetch(f"{url}/")
        assert status == 200 and "OpenOSINT" in body, "GET / did not serve the web UI"
        assert f"{url}/" in (work / "web.log").read_text(), "banner did not print the real URL"
        print(f"ok  web UI up at {url}/")

        second = spawn(cmd, env, work, work / "busy.log")
        try:
            code = second.wait(timeout=FAIL_FAST_TIMEOUT_SECS)
        except subprocess.TimeoutExpired:
            stop(second)
            raise SystemExit("second instance on a busy port kept running") from None
        busy = (work / "busy.log").read_text()
        assert code != 0, "second instance on a busy port exited 0"
        assert "already in use" in busy and "--port" in busy, f"busy-port message unclear:\n{busy}"
        assert "http://" not in busy, f"busy-port run printed a URL:\n{busy}"
        print("ok  busy port fails clearly")
    finally:
        stop(first)


def check_mcp(runner: list[str], env: dict, work: Path, expected_version: str) -> None:
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "smoke", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    log = work / "mcp.log"
    kwargs = {"start_new_session": True} if os.name != "nt" else {}
    with log.open("w") as err:
        proc = subprocess.Popen(
            [*runner, "openosint-mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=err,
            env=env,
            cwd=work,
            text=True,
            **kwargs,
        )
    lines: queue.Queue[str] = queue.Queue()
    threading.Thread(
        target=lambda: [lines.put(line) for line in proc.stdout], daemon=True
    ).start()
    replies: dict = {}
    try:
        # Keep stdin open until both replies arrive: closing it early makes the
        # server exit before a slow first tools/list (graph import) is answered.
        proc.stdin.write("\n".join(json.dumps(r) for r in requests) + "\n")
        proc.stdin.flush()
        deadline = time.monotonic() + START_TIMEOUT_SECS
        while not {1, 2} <= replies.keys() and time.monotonic() < deadline:
            try:
                msg = json.loads(lines.get(timeout=1))
            except queue.Empty:
                continue
            except json.JSONDecodeError:
                continue
            replies[msg.get("id")] = msg
    finally:
        stop(proc)
    assert {1, 2} <= replies.keys(), f"MCP server did not answer:\n{log.read_text()}"
    version = replies[1]["result"]["serverInfo"]["version"]
    assert version == expected_version, f"MCP serverInfo.version {version} != {expected_version}"
    tools = replies[2]["result"]["tools"]
    assert len(tools) >= MIN_TOOLS, f"only {len(tools)} MCP tools listed"
    print(f"ok  MCP server {version} lists {len(tools)} tools")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--extra", help="install this extra, e.g. graph")
    args = parser.parse_args()

    wheel = args.wheel.resolve()
    version = wheel.name.split("-")[1]
    extras = f"[{args.extra}]" if args.extra else ""
    runner = ["uvx", "--from", f"openosint{extras} @ {wheel.as_uri()}"]

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        home, work = root / "home", root / "work"
        home.mkdir()
        work.mkdir()
        env = clean_env(home)
        check_web(runner, env, work)
        check_mcp(runner, env, work, version)
        leftovers = sorted(p.name for p in work.iterdir() if p.suffix != ".log")
        assert not leftovers, f"startup wrote files into the working directory: {leftovers}"
    print("smoke test passed")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        sys.exit(f"FAIL: {exc}")
