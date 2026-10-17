"""
Tracearr MCP Server

Exposes Tracearr's Public API v2 as MCP tools, so an MCP-compatible AI assistant
(e.g. Claude Code / Claude Desktop) can see who is watching what right now, browse
watch history, look up per-title and per-user play statistics, see what was recently
added, and check library sizes.

Every tool is read-only: the Public API v2 has no write endpoints, so nothing here
can change anything in Tracearr or on your media server.

Configuration is via environment variables:
  TRACEARR_URL        e.g. http://192.168.1.50:3000 (required)
  TRACEARR_API_KEY    Tracearr > Settings > General > API key, format
                      `trr_pub_<token>` (required). It must belong to an owner
                      account, otherwise Tracearr answers 403.
  MCP_HOST            interface to bind to (default 0.0.0.0)
  MCP_PORT            port to listen on (default 8942)
  MCP_AUTH_TOKEN      shared secret required as `Authorization: Bearer <token>`
                      on every request (optional — if unset, and OIDC below is
                      not configured either, the server is open to anyone who
                      can reach it; see README for why that matters more than
                      usual here: this API returns people's viewing history and
                      email addresses). With OIDC configured it is accepted
                      next to OAuth tokens.
  OIDC_CONFIG_URL     OpenID Connect discovery URL of the identity provider, e.g.
                      https://auth.example.com/application/o/tracearr-mcp/.well-known/openid-configuration
  OIDC_CLIENT_ID      client id of this server at the identity provider
  OIDC_CLIENT_SECRET  client secret of this server at the identity provider
  MCP_PUBLIC_URL      the URL clients reach this server at, e.g.
                      https://tracearr-mcp.example.com (required with OIDC)

Tracearr's Public API v2 needs Tracearr 2.0.0 or later (earlier versions serve v1
only). It lives at a fixed `/api/v2/public` prefix, so there is no API-version
setting to configure. Auth is a Bearer API key (`trr_pub_...`). Tracearr rate-limits
one budget per key across the whole v2 surface, so a 429 is reported as such rather
than as a generic failure.

Transport: streamable-http. This runs as a standing network service (bind
0.0.0.0 inside the container; publish the port only on your internal
network/VLAN — never forward it externally) rather than being spawned
per-client over stdio, so any MCP client on the LAN can connect to
http://<host>:<port>/mcp.

Auth comes in two flavours:
- OIDC_* set: the SDK's OAuth support (mcp.server.auth) with this server as the
  authorization server and the login delegated to the OIDC provider (see
  oidc.py). This is what a server published through a reverse proxy, and used
  as a claude.ai connector, needs.
- Only MCP_AUTH_TOKEN set: a single shared bearer token checked by plain
  middleware, for trusted LAN clients.
"""

import asyncio
import hmac
import os
import sys
from typing import Any
from urllib.parse import quote

import httpx
import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from oidc import CALLBACK_PATH, OIDCProvider


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"error: required environment variable {name} is not set", file=sys.stderr)
        sys.exit(1)
    return value


TRACEARR_URL = _require_env("TRACEARR_URL").rstrip("/")
TRACEARR_API_KEY = _require_env("TRACEARR_API_KEY")
MCP_HOST = os.environ.get("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.environ.get("MCP_PORT", "8942"))
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN")

OIDC_SETTINGS = ("OIDC_CONFIG_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "MCP_PUBLIC_URL")
OIDC_ENABLED = any(os.environ.get(name) for name in OIDC_SETTINGS[:3])
if OIDC_ENABLED:
    # Half an OIDC configuration is a mistake, not a request to run without
    # auth: refuse to start rather than fall back to something weaker.
    OIDC_CONFIG_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, MCP_PUBLIC_URL = (
        _require_env(name) for name in OIDC_SETTINGS
    )
    MCP_PUBLIC_URL = MCP_PUBLIC_URL.rstrip("/")

# Page-size ceilings the API documents: 100 for most cursor-paginated endpoints,
# 1000 for watched-media (its rows are far smaller).
MAX_PAGE_SIZE = 100
MAX_WATCHED_MEDIA_PAGE_SIZE = 1000

INSTRUCTIONS = (
    "Read-only tools for Tracearr, which tracks who watches what on the media server. The data is "
    "personal (viewing history, usernames, email addresses): share only what the user asked for. "
    "Paginated tools return meta.nextCursor; pass it back as `cursor` for the next page (null means "
    "no more). A media `ref` is a canonical media UUID or a provider ref like movie:tmdb:584 or "
    "show:tvdb:81189; seasons have no provider ref, so get their UUID from media_children of the show."
)

client = httpx.Client(
    base_url=f"{TRACEARR_URL}/api/v2/public",
    headers={"Authorization": f"Bearer {TRACEARR_API_KEY}"},
    timeout=30,
)

if OIDC_ENABLED:
    oidc_provider = OIDCProvider(
        config_url=OIDC_CONFIG_URL,
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        public_url=MCP_PUBLIC_URL,
        static_token=MCP_AUTH_TOKEN,
    )
    mcp = MCPServer(
        "tracearr",
        instructions=INSTRUCTIONS,
        auth_server_provider=oidc_provider,
        auth=AuthSettings(
            issuer_url=MCP_PUBLIC_URL,
            resource_server_url=f"{MCP_PUBLIC_URL}/mcp",
            # Tokens are only ever minted by this server, for this server.
            validate_token_resource=False,
            client_registration_options=ClientRegistrationOptions(enabled=True),
        ),
    )

    @mcp.custom_route(CALLBACK_PATH, methods=["GET"])
    async def oidc_callback(request: Request) -> Response:
        return await oidc_provider.callback(request)

else:
    mcp = MCPServer("tracearr", instructions=INSTRUCTIONS)


def _error_detail(response: httpx.Response) -> str:
    """Tracearr's own explanation for an error response, whatever shape it uses."""
    try:
        body = response.json()
    except ValueError:
        return response.text[:300] or "no detail given"
    if isinstance(body, dict):
        for key in ("message", "detail", "error"):
            value = body.get(key)
            if isinstance(value, dict):
                value = value.get("message")
            if value:
                return str(value)[:300]
    return str(body)[:300]


def _get(path: str, **params: Any) -> Any:
    """GET a Public API v2 path and return its JSON.

    Parameters whose value is None are dropped, so tools can pass every optional
    argument straight through. Failures become readable tool errors.
    """
    query = {name: value for name, value in params.items() if value is not None}
    try:
        response = client.get(path, params=query)
    except httpx.RequestError as error:
        raise ToolError(f"Cannot reach Tracearr at {TRACEARR_URL}: {error}") from error

    status = response.status_code
    if status == 401:
        raise ToolError("Tracearr rejected the API key (HTTP 401): it is invalid, revoked or missing.")
    if status == 403:
        raise ToolError(
            "Tracearr refused the request (HTTP 403): the API key is not associated with an owner account."
        )
    if status == 404:
        raise ToolError(f"Not found in Tracearr (HTTP 404): {_error_detail(response)}")
    if status == 429:
        raise ToolError(
            "Tracearr's rate limit was hit (HTTP 429). Its budget is shared across the whole v2 API for this "
            "key, so wait a little before trying again."
        )
    if status >= 400:
        raise ToolError(f"Tracearr returned HTTP {status}: {_error_detail(response)}")
    return response.json()


def _ref(ref: str) -> str:
    """A media ref as a safe URL path segment (keeps the `:` of provider refs)."""
    if not ref or not ref.strip():
        raise ToolError("ref is required: a media UUID or a provider ref like movie:tmdb:584")
    return quote(ref.strip(), safe=":")


def _page_size(page_size: int | None, cap: int = MAX_PAGE_SIZE) -> int | None:
    """Clamp to what the API accepts, so an over-large request still returns a page."""
    return None if page_size is None else min(max(page_size, 1), cap)


@mcp.tool()
def active_streams(server_id: str | None = None, summary_only: bool = False) -> dict:
    """List the streams playing right now, each with user, title, player, and whether it is
    transcoding, direct streaming or direct playing.

    server_id: only this media server (UUID). summary_only: return just the totals (streams,
    transcodes, direct streams/plays, total bitrate, per-server breakdown) without the stream list.
    """
    return _get("/streams", server_id=server_id, summary=True if summary_only else None)


@mcp.tool()
def watch_history(
    user_id: str | None = None,
    server_id: str | None = None,
    media_id: str | None = None,
    rating_key: str | None = None,
    imdb_id: str | None = None,
    tmdb_id: int | None = None,
    tvdb_id: int | None = None,
    media_type: str | None = None,
    watched: bool | None = None,
    since: str | None = None,
    until: str | None = None,
    cursor: str | None = None,
    page_size: int | None = None,
) -> dict:
    """Watch history as plays, newest first. One record per play (a resume chain); plays where no
    part reached 2 minutes are excluded.

    Filters (all optional): user_id (Tracearr identity UUID), server_id, media_id (canonical media
    UUID; a show id matches all its episodes), rating_key, imdb_id, tmdb_id, tvdb_id, media_type
    (movie, episode, track, live, photo, unknown), watched (true/false: past the completion
    threshold, 85% by default), since / until (a date like 2026-09-01, or a full ISO datetime;
    until must not be before since).
    Paging: default 25 per page, max 100; pass meta.nextCursor back as `cursor` for the next page.
    """
    return _get(
        "/history",
        user_id=user_id,
        server_id=server_id,
        media_id=media_id,
        rating_key=rating_key,
        imdb_id=imdb_id,
        tmdb_id=tmdb_id,
        tvdb_id=tvdb_id,
        media_type=media_type,
        watched=watched,
        since=since,
        until=until,
        cursor=cursor,
        pageSize=_page_size(page_size),
    )


@mcp.tool()
def get_media(ref: str) -> dict:
    """Resolve a media ref to its canonical identity, the ids merged into it, and per-server
    availability (including removed copies). Shows also carry season and episode counts.

    ref: a canonical media UUID, or {movie|show|episode}:{imdb|tmdb|tvdb}:{id} such as
    movie:tmdb:584 or show:tvdb:81189. Seasons have no provider ref (see media_children).
    """
    return _get(f"/media/{_ref(ref)}")


@mcp.tool()
def media_children(ref: str) -> dict:
    """List a show's seasons (with episode counts) or a season's episodes. To reach a season, go
    show ref -> media_children -> season UUID -> media_children. Movies and episodes have no
    children (404). ref as in get_media."""
    return _get(f"/media/{_ref(ref)}/children")


@mcp.tool()
def media_stats(ref: str) -> dict:
    """Play counts, watch time and distinct viewers for a title across all_time, last_30 and
    last_7 UTC-day windows, each with a total and a per-server breakdown. Shows roll up their
    episodes. Cached by Tracearr for 60 seconds. ref as in get_media."""
    return _get(f"/media/{_ref(ref)}/stats")


@mcp.tool()
def media_watchers(ref: str, window: str = "all_time", server_id: str | None = None) -> dict:
    """Who watched a title: one entry per server account, ordered by watch time.

    window: all_time (default), last_30 or last_7 (UTC calendar days). server_id: only this server.
    ref as in get_media.
    """
    return _get(f"/media/{_ref(ref)}/watchers", window=window, server_id=server_id)


@mcp.tool()
def media_history(ref: str, cursor: str | None = None, page_size: int | None = None) -> dict:
    """Watch history for one title, newest first, one record per play. A show includes every
    episode and a season its episodes. Default 25 per page, max 100; pass meta.nextCursor back as
    `cursor`. ref as in get_media."""
    return _get(f"/media/{_ref(ref)}/history", cursor=cursor, pageSize=_page_size(page_size))


@mcp.tool()
def list_users(
    include_removed: bool = False, cursor: str | None = None, page_size: int | None = None
) -> dict:
    """List Tracearr identities, newest first, each with the media-server accounts it owns.
    Includes the email held on the identity (null when unset) and external_user_id (the media
    server's own user id, the stable key to correlate on).

    include_removed: also list identities whose every account has been removed.
    Default 25 per page, max 100; pass meta.nextCursor back as `cursor`.
    """
    return _get(
        "/users",
        include_removed=True if include_removed else None,
        cursor=cursor,
        pageSize=_page_size(page_size),
    )


@mcp.tool()
def get_user(user_id: str) -> dict:
    """One Tracearr identity by its id (UUID), with the accounts it owns."""
    return _get(f"/users/{_ref(user_id)}")


@mcp.tool()
def user_stats(user_id: str) -> dict:
    """Plays and watch time for an identity, summed across all its accounts, over all_time,
    last_30 and last_7 UTC-day windows, plus its top genres by play count. Cached 60 seconds."""
    return _get(f"/users/{_ref(user_id)}/stats")


@mcp.tool()
def user_history(user_id: str, cursor: str | None = None, page_size: int | None = None) -> dict:
    """Watch history for an identity across every account it owns, newest first, one record per
    play. Default 25 per page, max 100; pass meta.nextCursor back as `cursor`."""
    return _get(f"/users/{_ref(user_id)}/history", cursor=cursor, pageSize=_page_size(page_size))


@mcp.tool()
def recently_added(
    server_id: str | None = None,
    library_id: str | None = None,
    media_type: str | None = None,
    include_removed: bool = False,
    cursor: str | None = None,
    page_size: int | None = None,
) -> dict:
    """Library items ordered by the server-reported added date, newest first, each with its media
    identity.

    Filters (optional): server_id, library_id (a server's library id), media_type (movie, episode,
    season, show, artist, album, track, photo). include_removed also returns items since removed
    from the server. Default 25 per page, max 100; pass meta.nextCursor back as `cursor`.
    """
    return _get(
        "/recently-added",
        server_id=server_id,
        library_id=library_id,
        media_type=media_type,
        include_removed=True if include_removed else None,
        cursor=cursor,
        pageSize=_page_size(page_size),
    )


@mcp.tool()
def list_libraries() -> dict:
    """Per-library rollups for each server: item, movie, episode, show and track counts, total
    file size and per-resolution counts. Removed items are excluded. Cached 60 seconds."""
    return _get("/libraries")


@mcp.tool()
def watched_media(
    media_type: str,
    user_id: str | None = None,
    server_id: str | None = None,
    min_state: str | None = None,
    cursor: str | None = None,
    page_size: int | None = None,
) -> dict:
    """The distinct set of media with recorded watching, newest activity first, for matching
    against an external library by tmdb/tvdb/imdb id. Absence means unwatched.

    media_type (required): movie, show or episode. A movie/episode counts once a play passed the
    completion threshold (85% by default); a show once every episode present on the server has.
    user_id: scope to one identity (omit for the whole install). min_state: watched (default) or
    partial (also titles started but not finished).
    Default 100 per page, max 1000; pass meta.nextCursor back as `cursor`.
    """
    return _get(
        "/watched-media",
        media_type=media_type,
        user_id=user_id,
        server_id=server_id,
        min_state=min_state,
        cursor=cursor,
        pageSize=_page_size(page_size, MAX_WATCHED_MEDIA_PAGE_SIZE),
    )


# Paths that must stay reachable without MCP_AUTH_TOKEN, so Docker's own
# HEALTHCHECK, Dockhand's health probe, etc. don't need the secret. (With OIDC
# the SDK only guards /mcp, so these are open there too.)
UNAUTHENTICATED_PATHS = {"/health", "/ready"}


@mcp.custom_route("/health", methods=["GET"])
async def health(request: Request) -> Response:
    """Liveness check: the process is up and serving HTTP. Does not call Tracearr."""
    return JSONResponse({"status": "ok"})


@mcp.custom_route("/ready", methods=["GET"])
async def ready(request: Request) -> Response:
    """Readiness check: TRACEARR_URL is reachable and TRACEARR_API_KEY is accepted.

    Uses the streams summary, which is the cheapest authenticated call the API offers.
    """
    try:
        response = client.get("/streams", params={"summary": True}, timeout=5)
        response.raise_for_status()
    except httpx.HTTPStatusError as error:
        status_code = error.response.status_code
        if status_code == 401:
            reason = "invalid or revoked Tracearr API key"
        elif status_code == 403:
            reason = "Tracearr API key is not associated with an owner account"
        elif status_code == 404:
            reason = "Tracearr has no /api/v2/public API (needs Tracearr 2.0.0 or later)"
        elif status_code == 429:
            reason = "Tracearr rate limit hit"
        else:
            reason = f"Tracearr returned HTTP {status_code}"
        return JSONResponse(
            {"status": "error", "reachable": True, "authenticated": status_code not in (401, 403), "error": reason},
            status_code=503,
        )
    except httpx.RequestError as error:
        return JSONResponse(
            {
                "status": "error",
                "reachable": False,
                "authenticated": False,
                "error": f"cannot reach Tracearr at {TRACEARR_URL}: {error}",
            },
            status_code=503,
        )

    return JSONResponse(
        {
            "status": "ok",
            "reachable": True,
            "authenticated": True,
            "tracearr": {"url": TRACEARR_URL, "apiVersion": "v2"},
        }
    )


class BearerTokenMiddleware(BaseHTTPMiddleware):
    """Require `Authorization: Bearer <MCP_AUTH_TOKEN>` on every request except
    the health/readiness endpoints, which are meant to be publicly pollable."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path in UNAUTHENTICATED_PATHS:
            return await call_next(request)

        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(token, MCP_AUTH_TOKEN):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


def build_app():
    """Build the ASGI app (routes + auth middleware). Split out from __main__ so
    tests can exercise the real, fully-wired app without going through uvicorn."""
    app = mcp.streamable_http_app(host=MCP_HOST)

    if OIDC_ENABLED:
        # The SDK already wired the OAuth routes and token check into the app.
        print(f"Auth enabled: OAuth via OIDC provider {OIDC_CONFIG_URL}", file=sys.stderr)
        if MCP_AUTH_TOKEN:
            print("MCP_AUTH_TOKEN is accepted as a bearer token as well", file=sys.stderr)
    elif MCP_AUTH_TOKEN:
        app.add_middleware(BearerTokenMiddleware)
        print("Auth enabled: Authorization: Bearer <token> required", file=sys.stderr)
    else:
        print("WARNING: neither OIDC nor MCP_AUTH_TOKEN is set — server is open to anyone who can reach it", file=sys.stderr)

    return app


if __name__ == "__main__":
    tool_names = [tool.name for tool in asyncio.run(mcp.list_tools())]
    print(f"Tools available ({len(tool_names)}, all read-only): {', '.join(tool_names)}", file=sys.stderr)
    uvicorn.run(build_app(), host=MCP_HOST, port=MCP_PORT)
