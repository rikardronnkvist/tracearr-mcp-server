# tracearr-mcp-server

> Fork of [Barrow1990/tracearr-mcp-server](https://github.com/Barrow1990/tracearr-mcp-server)
> that adds **OAuth login through an OpenID Connect provider** (built for
> [Authentik](https://goauthentik.io)), so the server can be published through a
> reverse proxy such as Traefik and added as a custom connector in claude.ai.

A minimal [Model Context Protocol](https://modelcontextprotocol.io) server that
connects to Tracearr (who watches
what on your Plex/Jellyfin/Emby servers: live streams, watch history, per-user and
per-title stats), packaged for Docker. **Every tool is read-only** — Tracearr's
Public API v2 has no write endpoints, so nothing here can change anything in
Tracearr or on your media server.

It runs as a standing network service (streamable-http transport, not stdio),
so any MCP client can connect to `http://<host>:<port>/mcp` (or, with OIDC and a
reverse proxy, `https://<public-host>/mcp`) — the container isn't spawned per-client, and
container lifecycle/updates can be handed off to a tool like
[Dockhand](https://dockhand.pro).

## API assumptions

Built against Tracearr's **Public API v2** (`/api/v2/public`, OpenAPI 3.0,
version 2.0.0), which needs **Tracearr 2.0.0 or later** — earlier versions serve
API v1 only and `/ready` will say so (HTTP 404). Auth is a Bearer API key
(`trr_pub_<token>`) from **Tracearr > Settings > General**. The key must belong to
an owner account, otherwise Tracearr answers 403.

There's no server-reported API version to negotiate (the `/api/v2/public` prefix is
fixed), so there is no version environment variable. Tracearr rate-limits **one
budget per key across the whole v2 surface**; a 429 is reported to the AI as
exactly that, with a hint to wait.

## Tools

| Tool | Description |
|---|---|
| `active_streams` | Streams playing right now (user, title, player, transcode/direct), or just the totals with `summary_only` |
| `watch_history` | Watch history as plays, newest first; filter by user, server, media, provider ids, type, watched state, date range |
| `get_media` | Resolve a media ref to its canonical identity, merged ids and per-server availability |
| `media_children` | A show's seasons, or a season's episodes |
| `media_stats` | Play counts, watch time and distinct viewers over all-time / 30 days / 7 days |
| `media_watchers` | Who watched a title, ordered by watch time |
| `media_history` | Watch history for one title |
| `list_users` / `get_user` | Tracearr identities with their media-server accounts (and email, when set) |
| `user_stats` | An identity's plays and watch time over the same windows, plus top genres |
| `user_history` | An identity's watch history across all its accounts |
| `recently_added` | Recently added library items, newest first |
| `list_libraries` | Per-library counts, sizes and resolutions |
| `watched_media` | The set of watched (or started) media, for matching against an external library by tmdb/tvdb/imdb id |

A media `ref` is a canonical media UUID or a provider ref such as `movie:tmdb:584`
or `show:tvdb:81189`. Seasons have no provider ref: go show → `media_children` →
season UUID → `media_children`. Paginated tools return `meta.nextCursor`; pass it
back as `cursor` for the next page. Page sizes are clamped to what the API accepts
(100, or 1000 for `watched_media`).

## Privacy

This API returns **people's viewing history, usernames and email addresses**.
Configure OIDC (below) so only people your identity provider lets in can read it —
or, on a LAN only, at least set `MCP_AUTH_TOKEN`. Never publish the port without
one of them. The server's own instructions tell
the AI to share only what you asked for, but that is guidance to the AI, not a
control — the token and the network boundary are the controls.

## Health endpoints

Two plain HTTP endpoints, reachable without `MCP_AUTH_TOKEN` (so Docker's
`HEALTHCHECK`, Dockhand, or any other monitor can poll them without the secret):

| Endpoint | Checks | Healthy | Unhealthy |
|---|---|---|---|
| `GET /health` | The process is up and serving HTTP. Does **not** call Tracearr. | `200 {"status": "ok"}` | (doesn't respond) |
| `GET /ready` | `TRACEARR_URL` is reachable and `TRACEARR_API_KEY` is accepted (via the streams summary, the cheapest authenticated call). | `200 {"status": "ok", "reachable": true, "authenticated": true, "tracearr": {...}}` | `503 {"status": "error", "reachable": ..., "authenticated": ..., "error": "..."}` |

`/ready` says which of these it was: invalid or revoked key (401), key without an
owner account (403), Tracearr too old to have the v2 API (404), rate limited (429),
or unreachable.

## Authentication

Two modes, picked by which variables are set:

| Mode | Set | For |
|---|---|---|
| **OAuth via OIDC** | `OIDC_CONFIG_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `MCP_PUBLIC_URL` | Publishing through a reverse proxy; claude.ai connectors, Claude Desktop/Code with browser login |
| **Shared secret** | only `MCP_AUTH_TOKEN` | Trusted clients on a LAN |

Neither set = **no auth**; the server logs a warning on startup. Setting only some
of the `OIDC_*` variables is treated as a mistake: the server refuses to start.

### OAuth via OIDC

The server acts as the OAuth 2.1 authorization server MCP clients expect —
discovery metadata (`/.well-known/oauth-protected-resource/mcp`,
`/.well-known/oauth-authorization-server`), Dynamic Client Registration
(`/register`), `/authorize` and `/token` — and delegates the actual login to your
OIDC provider:

1. The MCP client registers itself and sends the browser to `/authorize`.
2. The server redirects to the OIDC provider (as client `OIDC_CLIENT_ID`, with PKCE).
3. The user logs in there; the provider decides whether they may use the app at
   all (in Authentik: the application's policy/group/user bindings).
4. The provider redirects to `<MCP_PUBLIC_URL>/oauth/callback`. The server redeems
   the code with `OIDC_CLIENT_SECRET`, checks the ID token (issuer, audience,
   expiry, nonce) and returns the MCP client to its own redirect URI with a code.
5. The client exchanges that for an access token (1 hour) and a refresh token (30 days).

Because the MCP client gets its own registration from this server, nothing has to
be configured per client in the OIDC provider — one OAuth2 provider/application
covers claude.ai, Claude Desktop, Claude Code and anything else.

**Stateless.** Client registrations, codes and tokens are HMAC-signed blobs, not
rows in a store, so the container needs no volume and restarts/redeploys don't
log anyone out. The signing key is derived from `OIDC_CLIENT_SECRET`, which has
two consequences:

- Tokens can't be revoked individually before they expire. Disabling a user in
  the OIDC provider stops new logins and refreshes from them only once their
  refresh token runs out (≤ 30 days).
- **Rotating the client secret in the OIDC provider (and in `OIDC_CLIENT_SECRET`)
  logs everyone out immediately** — that's the kill switch.

`MCP_AUTH_TOKEN`, if set too, is still accepted as a bearer token next to OAuth —
handy for scripts or clients that can only send a fixed header.

### Setting up Authentik

1. **Applications → Providers → Create → OAuth2/OpenID Provider**
   - Client type: **Confidential**
   - Redirect URIs: `strict` — `https://tracearr-mcp.example.com/oauth/callback`
     (your `MCP_PUBLIC_URL` + `/oauth/callback`)
   - Scopes: the defaults (`openid`, `email`, `profile`) are enough
   - Note the **Client ID** and **Client Secret**
2. **Applications → Applications → Create**, slug e.g. `tracearr-mcp`, with the
   provider above. Bind the users or groups who may use it (without bindings,
   every Authentik user can log in).
3. The discovery URL is
   `https://<authentik-host>/application/o/<slug>/.well-known/openid-configuration`
   — that's `OIDC_CONFIG_URL`.

Any other OIDC provider (Keycloak, Authelia, Entra ID, …) works the same way: a
confidential client with the callback URL as redirect URI, and its discovery URL.

### Shared secret

Set `MCP_AUTH_TOKEN` (a random shared secret — `openssl rand -hex 32`) and every
request must carry `Authorization: Bearer <token>` or the server returns `401`.
This is a small Starlette middleware in front of the MCP app. It is a separate
secret from `TRACEARR_API_KEY` — the latter authenticates *this server* to
Tracearr, the former authenticates *MCP clients* to this server. In this mode the
trust boundary is the network:

- **Do not** publish this port through any reverse proxy, port-forward, or
  anything else reachable from outside your LAN/VLAN — use OIDC for that.
- Bind the compose `ports:` mapping to a specific internal interface (e.g.
  `192.168.1.50:8942:8942`) if you want to be stricter.

## Configuration

Environment variables (see `.env.example`):

| Variable | Required | Default | Description |
|---|---|---|---|
| `TRACEARR_URL` | yes | — | e.g. `http://192.168.1.50:3000` |
| `TRACEARR_API_KEY` | yes | — | Tracearr > Settings > General (`trr_pub_...`), owner account |
| `MCP_HOST` | no | `0.0.0.0` | Interface the server binds to inside the container |
| `MCP_PORT` | no | `8942` | Port the server listens on |
| `MCP_AUTH_TOKEN` | no | — | Shared secret accepted as `Authorization: Bearer <token>`. With neither this nor OIDC set = no auth (see above) |
| `OIDC_CONFIG_URL` | for OAuth | — | OIDC discovery URL, e.g. `https://auth.example.com/application/o/tracearr-mcp/.well-known/openid-configuration` |
| `OIDC_CLIENT_ID` | for OAuth | — | Client ID of this server at the OIDC provider |
| `OIDC_CLIENT_SECRET` | for OAuth | — | Client secret of this server at the OIDC provider (also the token signing key, see above) |
| `MCP_PUBLIC_URL` | for OAuth | — | The URL clients reach this server at, e.g. `https://tracearr-mcp.example.com` — no `/mcp` suffix |

**Compose and `$`.** Docker Compose interpolates `$` in `.env` / `.env.dockhand`
values, so a secret containing `$` is silently truncated (`abc$Xy1def` becomes
`abc`). Write `$$` for a literal `$`, or single-quote the value. Generated
`trr_pub_...` keys and `openssl rand -hex` tokens don't contain `$`.

## Image

Built for `linux/amd64` and `linux/arm64` and pushed to
`ghcr.io/rikardronnkvist/tracearr-mcp-server` by
[`.github/workflows/ci.yml`](.github/workflows/ci.yml), after the tests pass:

| Trigger | Tags published |
|---|---|
| Release `vX.Y.Z` published | `:X.Y.Z`, `:X.Y`, `:X` and `:latest` |
| Push to `main` | `:main` and `:main-<commit-sha>` |
| Push to `dev` | `:dev` and `:dev-<commit-sha>` |

`:latest` is always the newest **release**; branch builds never touch it. Pin a
version (`:1.0.0`, or `:1` to follow 1.x) in production. The image is a
three-stage build that ends on a `scratch` base.

## Running in Docker Swarm behind Traefik

Add the service to the same stack as Tracearr, so it reaches Tracearr by service
name over the stack network and Traefik publishes it with TLS:

```yaml
services:
  tracearr-mcp:
    image: ghcr.io/rikardronnkvist/tracearr-mcp-server:1
    environment:
      TRACEARR_URL: http://tracearr:3000
      TRACEARR_API_KEY: trr_pub_...
      MCP_PUBLIC_URL: https://tracearr-mcp.example.com
      OIDC_CONFIG_URL: https://auth.example.com/application/o/tracearr-mcp/.well-known/openid-configuration
      OIDC_CLIENT_ID: ...
      OIDC_CLIENT_SECRET: ...
    networks: [default, traefik]
    deploy:
      replicas: 1
      labels:
        traefik.enable: "true"
        traefik.swarm.network: traefik
        traefik.http.routers.tracearr-mcp.rule: Host(`tracearr-mcp.example.com`)
        traefik.http.routers.tracearr-mcp.entrypoints: websecure
        traefik.http.routers.tracearr-mcp.tls.certresolver: le
        traefik.http.services.tracearr-mcp.loadbalancer.server.port: "8942"

networks:
  traefik:
    external: true
```

- No `ports:` — Traefik reaches the container over the `traefik` network.
- claude.ai connects **from Anthropic's cloud**, so the router must be reachable
  from the internet: don't put an IP allow-list middleware (LAN-only) on it. OAuth
  is what protects it. Clients on your own network only (Claude Code/Desktop on
  the LAN) can keep such a middleware.
- `/health` and `/ready` are reachable without auth, through Traefik too. They
  reveal nothing but whether Tracearr is up.
- More than one replica works (nothing is stored in the container).

## Running with Docker Compose

```bash
cp .env.example .env   # fill in TRACEARR_URL / TRACEARR_API_KEY / MCP_AUTH_TOKEN
docker compose up -d --pull always
```

The server is then reachable at `http://<docker-host>:8942/mcp` from anything
on your internal network.

## Managing with Dockhand

Point Dockhand at `ghcr.io/rikardronnkvist/tracearr-mcp-server` and let it track
new tags. **Make the GHCR package public**, or every pull will need `docker
login ghcr.io` with a PAT on each deploy host. Set a restart policy of
`unless-stopped` (already in `docker-compose.yml`). The `.env` / `.env.dockhand`
precedence works as in the other MCP-server repos.

## Connecting a client

### claude.ai (custom connector)

With OIDC configured: **Settings → Connectors → Add custom connector**, URL
`https://tracearr-mcp.example.com/mcp`. Leave the OAuth client ID/secret fields
empty — claude.ai registers itself. Connecting opens the Authentik login.

### Claude Code

With OIDC (opens the browser for login on first use, via `/mcp`):

```bash
claude mcp add tracearr -s user --transport http https://tracearr-mcp.example.com/mcp
```

With the shared secret:


```bash
claude mcp add tracearr -s user --transport http http://<docker-host>:8942/mcp \
  --header "Authorization: Bearer <MCP_AUTH_TOKEN>"
```
(Drop the `--header` flag if you're running with `MCP_AUTH_TOKEN` unset.)

### Claude Desktop

Claude Desktop's built-in config expects a locally-spawned `command`, so for
a network server like this you'll need an HTTP-to-stdio bridge such as
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote):

```json
{
  "mcpServers": {
    "tracearr": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote", "http://<docker-host>:8942/mcp",
        "--header", "Authorization: Bearer <MCP_AUTH_TOKEN>"
      ]
    }
  }
}
```

## Running without Docker

```bash
pip install -r requirements.txt
TRACEARR_URL=http://192.168.1.50:3000 TRACEARR_API_KEY=trr_pub_your_key \
MCP_AUTH_TOKEN=your-shared-secret python server.py
```

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

- `tests/test_tools.py` — every tool's request shape (path, parameters, dropped
  `None`s, page-size clamping, safe path segments) and error mapping, against a
  mocked Tracearr (`httpx.MockTransport`, no extra mocking library needed).
- `tests/test_http.py` — `/health`, `/ready`, and the bearer-auth middleware, via
  `server.build_app()` (the exact app `__main__` runs) through Starlette's
  `TestClient`.
- `tests/test_oidc.py` — the whole OAuth flow (registration, `/authorize`, OIDC
  callback, `/token`, refresh, `/mcp` with the token) against a mocked OIDC
  provider, plus forged/replayed codes and tokens and bad ID tokens.
- `tests/test_live_tracearr.py` — **opt-in** contract tests against a real
  Tracearr, to catch drift if an upgrade renames a field these tools rely on.
  Skipped by default; run with:
  ```bash
  RUN_LIVE_TRACEARR_TESTS=1 TRACEARR_URL=http://192.168.1.50:3000 \
  TRACEARR_API_KEY=<real trr_pub_... key> python -m pytest tests/test_live_tracearr.py -v
  ```

CI (`.github/workflows/ci.yml`) runs the mocked suite on every push/PR to `main`
and `dev`; the GHCR build only runs after it passes.

## Branch flow

- **`dev`** is where changes land first. Every push to `dev` runs the tests and
  publishes `:dev`.
- **`main`** changes through a pull request **from `dev`**; the `source-branch` check
  ([`enforce-dev-to-main.yml`](.github/workflows/enforce-dev-to-main.yml)) fails any
  pull request into `main` that comes from another branch or from a fork. Make it a
  required status check in branch protection to enforce it.
- Merge `dev` into `main` with a **merge commit**, not squash or rebase: squashing
  rewrites `dev`'s history, so `dev` and `main` diverge and every later pull
  request hits conflicts.

## Releasing

Publish a GitHub release with a `vX.Y.Z` tag (e.g. `v1.0.0`) from `main`. CI runs
the tests and publishes the versioned image tags and `:latest`.

## License

MIT — original work © Barrow1990, see [LICENSE](LICENSE).
