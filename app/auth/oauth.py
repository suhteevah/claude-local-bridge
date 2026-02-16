"""Minimal OAuth 2.1 provider for Claude.ai remote MCP connector.

Single-user pass-through: no real login — auto-approves all auth requests.
Implements Dynamic Client Registration (RFC 7591), PKCE (RFC 7636),
Protected Resource Metadata (RFC 9728), and OAuth Authorization Server
Metadata (RFC 8414) — the minimum required for Claude.ai + Claude iOS.
"""

from __future__ import annotations

import hashlib
import base64
import secrets
import time
import logging
from typing import Optional

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

logger = logging.getLogger("bridge.oauth")

router = APIRouter()

# ── In-memory stores (single-user, single-process) ──────────────────────────

_clients: dict[str, dict] = {}          # client_id -> registration info
_auth_codes: dict[str, dict] = {}       # code -> {client_id, redirect_uri, code_challenge, expires}
_access_tokens: set[str] = set()        # valid access tokens
_refresh_tokens: dict[str, str] = {}    # refresh_token -> client_id

_server_url: str = ""                   # set by init()


def init(server_url: str):
    """Set the public-facing server URL (e.g. https://kokonoe.tailb85819.ts.net)."""
    global _server_url
    _server_url = server_url.rstrip("/")


def is_valid_token(token: str) -> bool:
    """Check if a Bearer token is valid."""
    return token in _access_tokens


# ═════════════════════════════════════════════════════════════════════════════
#  Discovery Endpoints
# ═════════════════════════════════════════════════════════════════════════════


def _protected_resource_metadata() -> dict:
    return {
        "resource": f"{_server_url}/mcp",
        "authorization_servers": [_server_url],
        "scopes_supported": [],
        "bearer_methods_supported": ["header"],
        "resource_name": "Claude Local Bridge",
    }


def _authorization_server_metadata() -> dict:
    return {
        "issuer": _server_url,
        "authorization_endpoint": f"{_server_url}/authorize",
        "token_endpoint": f"{_server_url}/token",
        "registration_endpoint": f"{_server_url}/register",
        "scopes_supported": [],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    }


@router.get("/.well-known/oauth-protected-resource/mcp/sse")
@router.get("/.well-known/oauth-protected-resource/mcp")
@router.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata():
    return JSONResponse(_protected_resource_metadata())


@router.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata():
    return JSONResponse(_authorization_server_metadata())


# ═════════════════════════════════════════════════════════════════════════════
#  Dynamic Client Registration (RFC 7591)
# ═════════════════════════════════════════════════════════════════════════════


@router.post("/register")
async def register_client(request: Request):
    body = await request.json()

    client_id = secrets.token_hex(16)
    client_secret = secrets.token_hex(32)

    client_info = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_id_issued_at": int(time.time()),
        "client_secret_expires_at": None,
        "redirect_uris": body.get("redirect_uris", []),
        "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "client_secret_post"),
        "grant_types": body.get("grant_types", ["authorization_code", "refresh_token"]),
        "response_types": body.get("response_types", ["code"]),
        "client_name": body.get("client_name", "Unknown"),
    }

    _clients[client_id] = client_info
    logger.info(f"Registered OAuth client: {client_info['client_name']} ({client_id})")

    return JSONResponse(client_info, status_code=201)


# ═════════════════════════════════════════════════════════════════════════════
#  Authorization Endpoint — auto-approve (single-user bridge)
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/authorize")
async def authorize(
    response_type: str = "code",
    client_id: str = "",
    redirect_uri: str = "",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    scope: str = "",
    resource: str = "",
):
    if client_id not in _clients:
        return JSONResponse({"error": "invalid_client"}, status_code=400)

    if code_challenge_method != "S256":
        return JSONResponse({"error": "invalid_request", "error_description": "Only S256 supported"}, status_code=400)

    # Generate authorization code
    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "expires": time.time() + 300,  # 5 min
    }

    logger.info(f"Auto-approved auth for client {client_id}, redirecting")

    # Redirect back to Claude with the code
    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}&state={state}"
    return RedirectResponse(location, status_code=302)


# ═════════════════════════════════════════════════════════════════════════════
#  Token Endpoint
# ═════════════════════════════════════════════════════════════════════════════


def _verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Verify PKCE S256: base64url(sha256(verifier)) == challenge."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return computed == code_challenge


@router.post("/token")
async def token_endpoint(request: Request):
    # Parse form-encoded body
    form = await request.form()
    grant_type = form.get("grant_type", "")
    client_id = form.get("client_id", "")
    client_secret = form.get("client_secret", "")

    # Validate client
    client = _clients.get(client_id)
    if not client or client["client_secret"] != client_secret:
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    if grant_type == "authorization_code":
        code = form.get("code", "")
        code_verifier = form.get("code_verifier", "")
        redirect_uri = form.get("redirect_uri", "")

        auth_code = _auth_codes.pop(code, None)
        if not auth_code:
            return JSONResponse({"error": "invalid_grant", "error_description": "Code not found or already used"}, status_code=400)

        if auth_code["expires"] < time.time():
            return JSONResponse({"error": "invalid_grant", "error_description": "Code expired"}, status_code=400)

        if auth_code["client_id"] != client_id:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        if auth_code["redirect_uri"] != redirect_uri:
            return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400)

        # PKCE verification
        if not _verify_pkce(code_verifier, auth_code["code_challenge"]):
            return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)

        # Issue tokens
        access_token = secrets.token_hex(32)
        refresh_token = secrets.token_hex(32)
        _access_tokens.add(access_token)
        _refresh_tokens[refresh_token] = client_id

        logger.info(f"Issued access token for client {client_id}")

        return JSONResponse({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 86400,  # 24 hours
            "refresh_token": refresh_token,
            "scope": "",
        })

    elif grant_type == "refresh_token":
        refresh_token = form.get("refresh_token", "")

        if refresh_token not in _refresh_tokens:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        if _refresh_tokens[refresh_token] != client_id:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        # Rotate tokens
        del _refresh_tokens[refresh_token]
        new_access = secrets.token_hex(32)
        new_refresh = secrets.token_hex(32)
        _access_tokens.add(new_access)
        _refresh_tokens[new_refresh] = client_id

        logger.info(f"Refreshed token for client {client_id}")

        return JSONResponse({
            "access_token": new_access,
            "token_type": "Bearer",
            "expires_in": 86400,
            "refresh_token": new_refresh,
            "scope": "",
        })

    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
