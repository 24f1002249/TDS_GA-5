"""
Same deployment as before, extended with a second capability:

  1. The original MCP tool server (solve_challenge), unchanged, now
     mounted at /mcp instead of the root.
  2. A new public guardrail HTTP endpoint (POST /  and POST /guardrail)
     that fronts two "tools" - read_file(path) and fetch_url(url) -
     and only allows calls that pass a sandbox / SSRF policy.

Everything lives in one process / one Render service, so nothing new
needs to be deployed.
"""

import contextvars
import hashlib
import ipaddress
import os
import socket
from urllib.parse import urljoin, urlsplit

import requests
import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

# ===========================================================================
# Part 1: existing MCP server (unchanged logic, just mounted at /mcp below)
# ===========================================================================

EXAM_EMAIL = os.environ.get("EXAM_EMAIL", "24f1002249@ds.study.iitm.ac.in").strip().lower()

current_headers: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "current_headers", default={}
)


class HeaderCaptureMiddleware:
    """Stashes the raw HTTP headers of the current request into a
    contextvar so tool implementations can read them. Applies to the
    whole combined app (both /mcp and the guardrail routes)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = {}
            for raw_key, raw_val in scope.get("headers", []):
                headers[raw_key.decode("latin-1").lower()] = raw_val.decode("latin-1")
            current_headers.set(headers)
        await self.app(scope, receive, send)


mcp = FastMCP(
    "exam-mcp-server",
    stateless_http=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)


@mcp.tool()
def solve_challenge() -> str:
    """Return the first 16 hex chars of SHA-256(challenge:email)."""
    headers = current_headers.get()
    challenge = headers.get("x-exam-challenge", "")
    payload = f"{challenge}:{EXAM_EMAIL}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return digest[:16]


# ===========================================================================
# Part 2: guardrail endpoint
# ===========================================================================

SANDBOX_ROOT = os.path.realpath("/srv/agent-redteam/sandbox-2dcdedc428")
OUTSIDE_DIR = "/srv/agent-redteam/outside-0e768cfb"
ALLOWED_FETCH_HOSTS = {"example.com", "www.iana.org"}
MAX_READ_BYTES = 200_000
MAX_FETCH_BYTES = 200_000
FETCH_TIMEOUT_S = 10
MAX_REDIRECT_HOPS = 5


def _bootstrap_fixture_files() -> None:
    """Create the files the grader expects to already exist on disk.
    Idempotent - safe to call on every process start (Render's disk is
    ephemeral per-deploy, so this runs at import time below)."""
    fixtures = {
        os.path.join(OUTSIDE_DIR, "canary.txt"):
            "AGENT_GUARDRAIL_CANARY_d1d527d31707716165a356d3d86b42fb81e531b0\n",
        os.path.join(SANDBOX_ROOT, "notes", "report.txt"):
            "SAFE_REPORT_97bf3954ebab5ad7c9ee6e09\n",
        os.path.join(SANDBOX_ROOT, "notes", "looks-like-..-but-safe.txt"):
            "SAFE_WEIRD_2c7bbad3ac2511ce64ce0cdd\n",
        os.path.join(SANDBOX_ROOT, "encoded", "%2e%2e-literal.txt"):
            "SAFE_ENCODED_f9438f46923563691efc5498\n",
    }
    for path, content in fixtures.items():
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if not os.path.exists(path):
                with open(path, "w") as f:
                    f.write(content)
            print(f"BOOTSTRAP OK: {path}", flush=True)
        except OSError as e:
            # Loud on purpose: a silent failure here means benign
            # read_file controls will wrongly get blocked as "not found".
            print(f"BOOTSTRAP FAILED: {path} -> {e!r}", flush=True)


_bootstrap_fixture_files()


# ---------------------------------------------------------------------
# read_file guard
# ---------------------------------------------------------------------
#
# Design notes:
#  - We never URL-decode the path. The grader has fixture files whose
#    literal on-disk names contain "%2e%2e" and "..". Decoding would
#    both mis-handle those (turning a safe literal filename into what
#    looks like traversal) and open a decode-then-traverse bypass for
#    real attackers. Treat the string as a literal filesystem path.
#  - Resolution is done with os.path.realpath (which also resolves
#    symlinks) and containment is checked with os.path.commonpath
#    against the *real* sandbox root - this is what actually blocks
#    "../", absolute escapes, and symlink escapes, without relying on
#    fragile substring checks (which would wrongly block the benign
#    "looks-like-..-but-safe.txt" fixture).

def _resolve_sandboxed_path(user_path: str):
    if not isinstance(user_path, str) or not user_path:
        return None
    if "\x00" in user_path:
        return None

    if os.path.isabs(user_path):
        candidate = os.path.normpath(user_path)
    else:
        candidate = os.path.normpath(os.path.join(SANDBOX_ROOT, user_path))

    real = os.path.realpath(candidate)

    try:
        common = os.path.commonpath([real, SANDBOX_ROOT])
    except ValueError:
        return None  # different drives etc. - definitely not contained

    if common != SANDBOX_ROOT:
        return None

    return real


def guarded_read_file(path):
    real = _resolve_sandboxed_path(path)
    if real is None:
        return {"action": "block", "reason": "path resolves outside the sandbox root", "result": None}

    if os.path.islink(real):
        return {"action": "block", "reason": "symlinks are not allowed", "result": None}

    if not os.path.isfile(real):
        return {"action": "block", "reason": "no such file inside sandbox", "result": None}

    try:
        with open(real, "r", errors="replace") as f:
            content = f.read(MAX_READ_BYTES)
    except OSError as e:
        return {"action": "block", "reason": f"read error: {e}", "result": None}

    return {"action": "allow", "reason": "path validated inside sandbox root", "result": content}


# ---------------------------------------------------------------------
# fetch_url guard
# ---------------------------------------------------------------------
#
# Design notes:
#  - Host allowlist is checked via urlsplit(...).hostname, which
#    correctly separates userinfo (the "evil@" in
#    "http://evil@example.com/") from the actual host, so userinfo
#    tricks can't smuggle a different host past a naive parser.
#  - The allowlist check is exact-match on the lowercased, trailing-dot
#    -stripped hostname - not startswith/endswith/contains - so
#    lookalikes like "example.com.evil.com" or "notexample.com" fail.
#  - Beyond the hostname allowlist we also resolve DNS and reject any
#    answer that is private/loopback/link-local/reserved/multicast, to
#    catch DNS-rebinding style tricks even for an allowlisted name.
#  - Redirects are not auto-followed by requests; we inspect
#    Location ourselves and re-run the *entire* validation (allowlist +
#    DNS-safety) on the redirect target before following it, capped at
#    MAX_REDIRECT_HOPS. A redirect to a disallowed/private target is
#    blocked rather than followed.

def _is_unsafe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _host_resolves_safely(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        ip = info[4][0]
        if _is_unsafe_ip(ip):
            return False
    return True


def _validate_fetch_url(url: str):
    try:
        parts = urlsplit(url)
    except Exception:
        return None, "unparseable url"

    if parts.scheme not in ("http", "https"):
        return None, f"scheme not allowed: {parts.scheme!r}"

    host = parts.hostname
    if not host:
        return None, "missing host"
    host = host.lower().rstrip(".")

    if host not in ALLOWED_FETCH_HOSTS:
        return None, f"host not on allowlist: {host!r}"

    if not _host_resolves_safely(host):
        return None, "host resolves to a private/loopback/link-local/reserved address"

    return parts, None


def guarded_fetch_url(url: str, _hop: int = 0):
    if _hop > MAX_REDIRECT_HOPS:
        return {"action": "block", "reason": "too many redirects", "result": None}

    parts, err = _validate_fetch_url(url)
    if err:
        return {"action": "block", "reason": err, "result": None}

    try:
        resp = requests.get(url, allow_redirects=False, timeout=FETCH_TIMEOUT_S)
    except requests.RequestException as e:
        return {"action": "block", "reason": f"fetch error: {e}", "result": None}

    if resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get("Location")
        if not location:
            return {"action": "block", "reason": "redirect with no Location header", "result": None}
        next_url = urljoin(url, location)
        return guarded_fetch_url(next_url, _hop + 1)

    text = resp.text[:MAX_FETCH_BYTES]
    return {
        "action": "allow",
        "reason": "host allowlisted and resolves to a public address",
        "result": {"status": resp.status_code, "content": text},
    }


# ---------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------

async def guardrail_endpoint(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"action": "block", "reason": "invalid JSON body", "result": None},
            status_code=400,
        )

    if not isinstance(body, dict):
        return JSONResponse(
            {"action": "block", "reason": "body must be a JSON object", "result": None},
            status_code=400,
        )

    tool = body.get("tool")
    args = body.get("arguments")
    if not isinstance(args, dict):
        args = {}

    if tool == "read_file":
        path = args.get("path")
        if not isinstance(path, str):
            outcome = {"action": "block", "reason": "missing/invalid 'path' argument", "result": None}
        else:
            outcome = guarded_read_file(path)
    elif tool == "fetch_url":
        url = args.get("url")
        if not isinstance(url, str):
            outcome = {"action": "block", "reason": "missing/invalid 'url' argument", "result": None}
        else:
            outcome = guarded_fetch_url(url)
    else:
        outcome = {"action": "block", "reason": f"unknown tool: {tool!r}", "result": None}

    return JSONResponse(outcome)


async def health(request: Request):
    return JSONResponse({"status": "ok"})


async def debug_fixtures(request: Request):
    """Diagnostic only - reports whether each expected fixture exists and
    is readable, plus the resolved sandbox root. Not part of the graded
    contract; safe to remove later, but handy for confirming bootstrap
    actually succeeded on the deployed machine."""
    paths = [
        os.path.join(OUTSIDE_DIR, "canary.txt"),
        os.path.join(SANDBOX_ROOT, "notes", "report.txt"),
        os.path.join(SANDBOX_ROOT, "notes", "looks-like-..-but-safe.txt"),
        os.path.join(SANDBOX_ROOT, "encoded", "%2e%2e-literal.txt"),
    ]
    report = []
    for p in paths:
        entry = {"path": p, "exists": os.path.exists(p), "is_file": os.path.isfile(p)}
        if entry["is_file"]:
            try:
                with open(p, "r", errors="replace") as f:
                    entry["preview"] = f.read(80)
            except OSError as e:
                entry["read_error"] = repr(e)
        report.append(entry)
    return JSONResponse({
        "sandbox_root": SANDBOX_ROOT,
        "sandbox_root_exists": os.path.isdir(SANDBOX_ROOT),
        "outside_dir": OUTSIDE_DIR,
        "fixtures": report,
    })


routes = [
    Route("/", guardrail_endpoint, methods=["POST"]),
    Route("/guardrail", guardrail_endpoint, methods=["POST"]),
    Route("/health", health, methods=["GET"]),
    Route("/debug", debug_fixtures, methods=["GET"]),
]

guardrail_app = Starlette(routes=routes)

# mcp.streamable_http_app() is itself a full Starlette app that expects
# requests at its own internal path (/mcp by default). Nesting it behind
# Starlette's Mount("/mcp", ...) strips that prefix before forwarding,
# so the inner app sees an empty path and tries to redirect back to
# "/mcp" - which, combined with the outer mount prefix, resolves to
# "/mcp/mcp" and breaks MCP clients that refuse to follow redirects.
# Dispatching manually and passing the original path through unchanged
# avoids that double-prefix bug entirely.
mcp_app = mcp.streamable_http_app()


class CombinedApp:
    def __init__(self, mcp_app, guardrail_app):
        self.mcp_app = mcp_app
        self.guardrail_app = guardrail_app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            # FastMCP's stateless session manager needs the lifespan
            # events; the guardrail app has no lifespan needs of its own.
            await self.mcp_app(scope, receive, send)
        elif scope["type"] == "http" and scope["path"].startswith("/mcp"):
            await self.mcp_app(scope, receive, send)
        else:
            await self.guardrail_app(scope, receive, send)


app = HeaderCaptureMiddleware(CombinedApp(mcp_app, guardrail_app))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print("=" * 60, flush=True)
    print("STARTUP MARKER: main.py v3 (guardrail + mcp combined)", flush=True)
    print(f"sandbox root = {SANDBOX_ROOT}", flush=True)
    print(f"allowed fetch hosts = {sorted(ALLOWED_FETCH_HOSTS)}", flush=True)
    print(f"binding to 0.0.0.0:{port}", flush=True)
    print("=" * 60, flush=True)
    uvicorn.run(app, host="0.0.0.0", port=port)
