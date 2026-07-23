"""
Minimal public MCP server exposing exactly one tool: solve_challenge.

Protocol: MCP Streamable HTTP transport (the modern, stateless-friendly
transport recommended for public deployments).

The tool reads the exam challenge from the raw HTTP request headers
(NOT from the JSON-RPC body) via an ASGI middleware that stashes the
per-request headers into a contextvar. Because uvicorn/ASGI gives each
inbound HTTP request its own asyncio Task, and contextvars snapshot at
task-creation time, concurrent requests never see each other's headers.
"""

import contextvars
import hashlib
import os

import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Your registered exam email, normalized (trimmed + lowercased) once at
# startup. Can be overridden via env var if you ever need to, but the
# default is already correct for this exam.
EXAM_EMAIL = os.environ.get("EXAM_EMAIL", "24f1002249@ds.study.iitm.ac.in").strip().lower()

# ---------------------------------------------------------------------------
# Per-request header capture
# ---------------------------------------------------------------------------

current_headers: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "current_headers", default={}
)


class HeaderCaptureMiddleware:
    """Stashes the raw HTTP headers of the current request into a
    contextvar so tool implementations (which don't get direct ASGI
    scope access via FastMCP's high-level decorator API) can read them.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = {}
            for raw_key, raw_val in scope.get("headers", []):
                headers[raw_key.decode("latin-1").lower()] = raw_val.decode("latin-1")
            current_headers.set(headers)
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# MCP server + the one required tool
# ---------------------------------------------------------------------------

# stateless_http=True: every HTTP request is handled independently, which
# is the simplest and most robust mode for a small public exam endpoint.
#
# The SDK's default DNS-rebinding protection only allows Host headers of
# "localhost"/"127.0.0.1", which rejects every request once this is
# deployed behind a public hostname (e.g. onrender.com). This is a public,
# unauthenticated exam endpoint by design, so that protection is disabled
# here rather than trying to allowlist Render's exact hostname.
mcp = FastMCP(
    "exam-mcp-server",
    stateless_http=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)


@mcp.tool()
def solve_challenge() -> str:
    """Return the first 16 hex chars of SHA-256(challenge:email).

    The challenge comes from the X-Exam-Challenge HTTP header on this
    specific tool call (read from the ASGI request, not the JSON-RPC
    tool-call arguments, which are intentionally empty).
    """
    headers = current_headers.get()
    challenge = headers.get("x-exam-challenge", "")

    payload = f"{challenge}:{EXAM_EMAIL}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return digest[:16]


# ---------------------------------------------------------------------------
# ASGI app
# ---------------------------------------------------------------------------

app = HeaderCaptureMiddleware(mcp.streamable_http_app())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
