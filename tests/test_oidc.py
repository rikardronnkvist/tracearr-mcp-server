"""Tests for OAuth via an OIDC provider (oidc.py), through the fully wired app.

server.py decides at import time whether OIDC is on, so the `oidc_server`
fixture sets the OIDC_* variables and reloads the module, then reloads it again
without them afterwards. "Authentik" is an httpx.MockTransport serving the
discovery document and the token endpoint.
"""

import base64
import hashlib
import importlib
import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from starlette.testclient import TestClient

import server

PUBLIC_URL = "https://tracearr-mcp.example.com"
ISSUER = "https://auth.example.com/application/o/tracearr-mcp/"
CONFIG_URL = f"{ISSUER}.well-known/openid-configuration"
CLIENT_REDIRECT = "http://localhost:33418/callback"
VERIFIER = "a" * 64
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()


def _jwt(claims: dict) -> str:
    def part(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'RS256'})}.{part(claims)}.signature"


class FakeAuthentik:
    """Discovery + token endpoint. `claims` overrides what the ID token says."""

    def __init__(self):
        self.claims: dict = {}
        self.token_requests: list[httpx.Request] = []
        self.nonce = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        if str(request.url) == CONFIG_URL:
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": "https://auth.example.com/application/o/authorize/",
                    "token_endpoint": "https://auth.example.com/application/o/token/",
                },
            )
        if request.url.path == "/application/o/token/":
            self.token_requests.append(request)
            claims = {
                "iss": ISSUER,
                "aud": "authentik-client-id",
                "sub": "user-123",
                "exp": time.time() + 300,
                "nonce": self.nonce,
                **self.claims,
            }
            return httpx.Response(200, json={"access_token": "upstream", "id_token": _jwt(claims)})
        return httpx.Response(404)


@pytest.fixture
def oidc_server(monkeypatch):
    monkeypatch.setenv("OIDC_CONFIG_URL", CONFIG_URL)
    monkeypatch.setenv("OIDC_CLIENT_ID", "authentik-client-id")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "authentik-client-secret")
    monkeypatch.setenv("MCP_PUBLIC_URL", PUBLIC_URL + "/")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "static-secret")
    importlib.reload(server)

    authentik = FakeAuthentik()
    server.oidc_provider.http = httpx.AsyncClient(transport=httpx.MockTransport(authentik.handler))
    server.client = httpx.Client(
        base_url=f"{server.TRACEARR_URL}/api/v2/public",
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"data": []})),
    )
    with TestClient(server.build_app(), base_url=PUBLIC_URL) as client:
        yield client, authentik

    monkeypatch.undo()
    importlib.reload(server)


def _register(client, **metadata) -> dict:
    response = client.post(
        "/register",
        json={"redirect_uris": [CLIENT_REDIRECT], "client_name": "test", **metadata},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _login(client, authentik, registration) -> str:
    """Run /authorize and the OIDC callback; return the redirect back to the client."""
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": CLIENT_REDIRECT,
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "state": "client-state",
            "scope": "tracearr",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    upstream = urlparse(response.headers["location"])
    query = {key: values[0] for key, values in parse_qs(upstream.query).items()}
    assert upstream.netloc == "auth.example.com"
    assert query["client_id"] == "authentik-client-id"
    assert query["redirect_uri"] == f"{PUBLIC_URL}/oauth/callback"
    assert query["code_challenge_method"] == "S256"
    assert "openid" in query["scope"].split()
    authentik.nonce = query["nonce"]

    response = client.get(
        "/oauth/callback", params={"code": "upstream-code", "state": query["state"]}, follow_redirects=False
    )
    assert response.status_code == 302, response.text
    return response.headers["location"]


def _code_from(location: str) -> str:
    redirect = urlparse(location)
    query = {key: values[0] for key, values in parse_qs(redirect.query).items()}
    assert f"{redirect.scheme}://{redirect.netloc}{redirect.path}" == CLIENT_REDIRECT
    assert query["state"] == "client-state"
    return query["code"]


def _redeem(client, registration, code) -> httpx.Response:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": CLIENT_REDIRECT,
        "code_verifier": VERIFIER,
        "client_id": registration["client_id"],
    }
    if registration.get("client_secret"):
        data["client_secret"] = registration["client_secret"]
    return client.post("/token", data=data)


def _initialize(client, token: str | None) -> httpx.Response:
    headers = {"Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
        },
    )


def test_metadata_points_clients_at_this_server(oidc_server):
    client, _ = oidc_server

    resource = client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert resource["resource"] == f"{PUBLIC_URL}/mcp"
    assert [url.rstrip("/") for url in resource["authorization_servers"]] == [PUBLIC_URL]

    metadata = client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["authorization_endpoint"] == f"{PUBLIC_URL}/authorize"
    assert metadata["token_endpoint"] == f"{PUBLIC_URL}/token"
    assert metadata["registration_endpoint"] == f"{PUBLIC_URL}/register"


def test_mcp_without_token_asks_for_oauth(oidc_server):
    client, _ = oidc_server

    response = _initialize(client, None)

    assert response.status_code == 401
    assert "oauth-protected-resource" in response.headers["www-authenticate"]


def test_health_and_ready_stay_open(oidc_server):
    client, _ = oidc_server

    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code in (200, 503)


@pytest.mark.parametrize("auth_method", ["none", "client_secret_post"])
def test_full_login_flow(oidc_server, auth_method):
    client, authentik = oidc_server
    registration = _register(client, token_endpoint_auth_method=auth_method)
    assert (registration.get("client_secret") is None) == (auth_method == "none")

    code = _code_from(_login(client, authentik, registration))
    tokens = _redeem(client, registration, code)

    assert tokens.status_code == 200, tokens.text
    body = tokens.json()
    assert body["token_type"].lower() == "bearer"
    assert _initialize(client, body["access_token"]).status_code == 200

    # The upstream exchange used this server's own Authentik credentials and PKCE.
    upstream = authentik.token_requests[-1]
    assert upstream.headers["authorization"].startswith("Basic ")
    assert b"code_verifier=" in upstream.content


def test_authorization_code_is_single_use(oidc_server):
    client, authentik = oidc_server
    registration = _register(client, token_endpoint_auth_method="none")
    code = _code_from(_login(client, authentik, registration))

    assert _redeem(client, registration, code).status_code == 200
    assert _redeem(client, registration, code).status_code == 400


def test_wrong_pkce_verifier_is_refused(oidc_server):
    client, authentik = oidc_server
    registration = _register(client, token_endpoint_auth_method="none")
    code = _code_from(_login(client, authentik, registration))

    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": CLIENT_REDIRECT,
            "code_verifier": "b" * 64,
            "client_id": registration["client_id"],
        },
    )
    assert response.status_code == 400


def test_code_cannot_be_redeemed_by_another_client(oidc_server):
    client, authentik = oidc_server
    registration = _register(client, token_endpoint_auth_method="none")
    other = _register(client, token_endpoint_auth_method="none", client_name="other")
    code = _code_from(_login(client, authentik, registration))

    assert _redeem(client, other, code).status_code == 400


def test_refresh_token(oidc_server):
    client, authentik = oidc_server
    registration = _register(client, token_endpoint_auth_method="none")
    tokens = _redeem(client, registration, _code_from(_login(client, authentik, registration))).json()

    refreshed = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": registration["client_id"],
        },
    )

    assert refreshed.status_code == 200, refreshed.text
    assert _initialize(client, refreshed.json()["access_token"]).status_code == 200


def test_static_token_still_works(oidc_server):
    client, _ = oidc_server

    assert _initialize(client, "static-secret").status_code == 200
    assert _initialize(client, "wrong").status_code == 401


def test_forged_tokens_are_refused(oidc_server):
    client, authentik = oidc_server
    registration = _register(client, token_endpoint_auth_method="none")
    access = _redeem(client, registration, _code_from(_login(client, authentik, registration))).json()["access_token"]
    body, _, mac = access.rpartition(".")

    assert _initialize(client, f"{body}.{mac[:-2]}xx").status_code == 401
    # A refresh token or client id is signed for a different purpose, so it is no access token.
    assert _initialize(client, registration["client_id"]).status_code == 401


@pytest.mark.parametrize(
    "claims",
    [{"iss": "https://evil.example.com/"}, {"aud": "someone-else"}, {"nonce": "replayed"}, {"exp": 1}],
)
def test_bad_id_token_is_refused(oidc_server, claims):
    client, authentik = oidc_server
    authentik.claims = claims
    registration = _register(client, token_endpoint_auth_method="none")

    location = _login(client, authentik, registration)

    query = parse_qs(urlparse(location).query)
    assert query["error"] == ["server_error"]
    assert "code" not in query


def test_login_denied_at_provider_goes_back_to_client(oidc_server):
    client, authentik = oidc_server
    registration = _register(client, token_endpoint_auth_method="none")
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": CLIENT_REDIRECT,
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "state": "client-state",
        },
        follow_redirects=False,
    )
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]

    response = client.get("/oauth/callback", params={"error": "access_denied", "state": state}, follow_redirects=False)

    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["client-state"]


def test_callback_with_tampered_state(oidc_server):
    client, _ = oidc_server

    assert client.get("/oauth/callback", params={"code": "x", "state": "forged.state"}).status_code == 400


def test_partial_oidc_config_refuses_to_start():
    env = {
        "PATH": "/usr/bin:/bin",
        "TRACEARR_URL": "http://test-tracearr:3000",
        "TRACEARR_API_KEY": "trr_pub_faketoken",
        "OIDC_CONFIG_URL": CONFIG_URL,
    }
    result = subprocess.run(
        [sys.executable, "-c", "import server"],
        cwd=Path(server.__file__).parent,
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "OIDC_CLIENT_ID" in result.stderr
