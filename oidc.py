"""
OAuth 2.1 for MCP clients, with the actual login delegated to an OpenID Connect
provider (built for Authentik, but any standards-compliant OIDC provider works).

This server is the OAuth authorization server MCP clients talk to: it serves
the discovery metadata, Dynamic Client Registration, /authorize and /token that
claude.ai, Claude Desktop/Code etc. expect. /authorize sends the browser on to
the OIDC provider, which authenticates the user and decides whether they may
use this application at all (in Authentik: the application's policy/group
bindings). The provider redirects back to /oauth/callback, and this server then
finishes the client's own authorization-code flow.

Everything this server issues — client registrations, authorization codes,
access and refresh tokens, the state it round-trips through the OIDC provider —
is an HMAC-signed, self-contained blob rather than a row in some store. That
keeps the container stateless: it survives restarts and redeploys without
logging every client out, needs no volume, and could run more than one
replica. The signing key is derived from OIDC_CLIENT_SECRET, so rotating that
secret in the OIDC provider also invalidates every token issued here.

The trade-off of being stateless: a token can't be revoked before it expires
(access tokens live ACCESS_TOKEN_TTL, refresh tokens REFRESH_TOKEN_TTL).
Blocking a user in the OIDC provider stops them from logging in again; rotating
OIDC_CLIENT_SECRET cuts off everyone immediately.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

CALLBACK_PATH = "/oauth/callback"
UPSTREAM_SCOPES = "openid profile email"

STATE_TTL = 10 * 60  # time the user has to log in at the OIDC provider
CODE_TTL = 5 * 60
ACCESS_TOKEN_TTL = 60 * 60
REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class _Client(OAuthClientInformationFull):
    """A registered client that may ask for any scope.

    Scopes carry no meaning here (every tool is read-only and an authenticated
    user gets all of them), and MCP clients disagree about which scopes to
    request, so refusing unregistered ones would only break logins.
    """

    def validate_scope(self, requested_scope: str | None) -> list[str] | None:
        return requested_scope.split() if requested_scope else None


class OIDCProvider:
    """OAuthAuthorizationServerProvider for the SDK's auth routes (see module docstring)."""

    def __init__(
        self,
        config_url: str,
        client_id: str,
        client_secret: str,
        public_url: str,
        static_token: str | None = None,
        http: httpx.AsyncClient | None = None,
    ):
        self.config_url = config_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.public_url = public_url.rstrip("/")
        self.callback_url = f"{self.public_url}{CALLBACK_PATH}"
        # MCP_AUTH_TOKEN keeps working next to OAuth, for clients that can only
        # send a fixed header (scripts, older clients).
        self.static_token = static_token
        self.http = http or httpx.AsyncClient(timeout=15)
        self._key = hmac.new(client_secret.encode(), b"tracearr-mcp-server signing key", hashlib.sha256).digest()
        self._metadata: dict[str, Any] | None = None
        # Authorization codes are single-use; stateless codes need a memory of
        # the ones already redeemed, for as long as they would otherwise be valid.
        self._used_codes: dict[str, float] = {}

    # --- signed blobs ------------------------------------------------------

    def _mac(self, purpose: str, body: str) -> str:
        return _b64encode(hmac.new(self._key, f"{purpose}.{body}".encode(), hashlib.sha256).digest())

    def _sign(self, purpose: str, payload: dict[str, Any]) -> str:
        body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
        return f"{body}.{self._mac(purpose, body)}"

    def _unsign(self, purpose: str, blob: str) -> dict[str, Any] | None:
        """The payload of a blob this server signed for `purpose`, or None if it
        is forged, meant for something else, or expired."""
        body, _, mac = blob.rpartition(".")
        if not body or not hmac.compare_digest(mac, self._mac(purpose, body)):
            return None
        try:
            payload = json.loads(_b64decode(body))
        except ValueError:
            return None
        if "exp" in payload and payload["exp"] < time.time():
            return None
        return payload

    def _client_ref(self, client_id: str) -> str:
        """A short stand-in for a client id (which embeds the whole registration)."""
        return _b64encode(hashlib.sha256(client_id.encode()).digest()[:18])

    # --- OIDC provider -----------------------------------------------------

    async def metadata(self) -> dict[str, Any]:
        """The OIDC provider's discovery document, fetched on first use so the
        server still starts while the provider is down."""
        if self._metadata is None:
            response = await self.http.get(self.config_url)
            response.raise_for_status()
            self._metadata = response.json()
        return self._metadata

    # --- client registration -----------------------------------------------

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # The SDK's registration handler has already minted a random id and
        # secret, and responds with this same object once we return. Replace
        # both with ones derived from the registration itself, so nothing has
        # to be stored to recognise the client later.
        registration = {
            "redirect_uris": [str(uri) for uri in client_info.redirect_uris or []],
            "token_endpoint_auth_method": client_info.token_endpoint_auth_method,
            "grant_types": client_info.grant_types,
            "response_types": client_info.response_types,
            "scope": client_info.scope,
            "client_name": client_info.client_name,
        }
        client_info.client_id = self._sign("client", registration)
        if client_info.client_secret is not None:
            client_info.client_secret = self._client_secret(client_info.client_id)

    def _client_secret(self, client_id: str) -> str:
        return self._mac("client-secret", client_id)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        registration = self._unsign("client", client_id)
        if registration is None:
            return None
        has_secret = registration.get("token_endpoint_auth_method") != "none"
        return _Client.model_validate(
            {
                **registration,
                "client_id": client_id,
                "client_secret": self._client_secret(client_id) if has_secret else None,
                "client_secret_expires_at": 0 if has_secret else None,
            }
        )

    # --- authorization -----------------------------------------------------

    def _upstream_verifier(self, nonce: str) -> str:
        # PKCE towards the OIDC provider. Derived rather than carried in the
        # state, because the state travels through the browser in plain sight.
        return self._mac("pkce", nonce)

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        try:
            authorization_endpoint = (await self.metadata())["authorization_endpoint"]
        except (httpx.HTTPError, ValueError, KeyError) as error:
            raise AuthorizeError("temporarily_unavailable", f"OIDC provider unavailable: {error}") from error

        nonce = secrets.token_urlsafe(16)
        state = self._sign(
            "state",
            {
                "client": self._client_ref(client.client_id),
                "redirect_uri": str(params.redirect_uri),
                "explicit": params.redirect_uri_provided_explicitly,
                "challenge": params.code_challenge,
                "state": params.state,
                "scopes": params.scopes or [],
                "resource": params.resource,
                "nonce": nonce,
                "exp": int(time.time()) + STATE_TTL,
            },
        )
        challenge = _b64encode(hashlib.sha256(self._upstream_verifier(nonce).encode()).digest())
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.callback_url,
                "scope": UPSTREAM_SCOPES,
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{authorization_endpoint}?{query}"

    async def callback(self, request: Request) -> Response:
        """Where the OIDC provider sends the browser back after login."""
        flow = self._unsign("state", request.query_params.get("state", ""))
        if flow is None:
            return PlainTextResponse("Login expired or invalid. Start again from your MCP client.", status_code=400)

        def back_to_client(**params: str | None) -> Response:
            return RedirectResponse(
                construct_redirect_uri(flow["redirect_uri"], state=flow["state"], **params), status_code=302
            )

        if "error" in request.query_params:
            return back_to_client(
                error="access_denied", error_description=request.query_params.get("error_description")
            )

        try:
            claims = await self._redeem_upstream_code(request.query_params.get("code", ""), flow["nonce"])
        except (httpx.HTTPError, ValueError, KeyError) as error:
            return back_to_client(error="server_error", error_description=f"OIDC login failed: {error}")

        code = self._sign(
            "code",
            {
                "client": flow["client"],
                "redirect_uri": flow["redirect_uri"],
                "explicit": flow["explicit"],
                "challenge": flow["challenge"],
                "scopes": flow["scopes"],
                "resource": flow["resource"],
                "sub": claims["sub"],
                "jti": secrets.token_urlsafe(12),
                "exp": int(time.time()) + CODE_TTL,
            },
        )
        return back_to_client(code=code)

    async def _redeem_upstream_code(self, code: str, nonce: str) -> dict[str, Any]:
        """Exchange the OIDC provider's code for the user's ID token claims."""
        metadata = await self.metadata()
        response = await self.http.post(
            metadata["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.callback_url,
                "code_verifier": self._upstream_verifier(nonce),
            },
            auth=(self.client_id, self.client_secret),
        )
        if response.status_code != 200:
            raise ValueError(f"token endpoint returned HTTP {response.status_code}: {response.text[:200]}")

        # The ID token comes straight from the provider's token endpoint over
        # TLS, which OIDC Core §3.1.3.7 accepts in place of checking its
        # signature; the claims themselves still have to be checked.
        id_token = response.json()["id_token"]
        claims = json.loads(_b64decode(id_token.split(".")[1]))
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if claims.get("iss") != metadata["issuer"]:
            raise ValueError("ID token issuer does not match the OIDC provider")
        if self.client_id not in audiences:
            raise ValueError("ID token was not issued for OIDC_CLIENT_ID")
        if claims.get("exp", 0) < time.time():
            raise ValueError("ID token has expired")
        if claims.get("nonce") != nonce:
            raise ValueError("ID token nonce does not match the login request")
        if not claims.get("sub"):
            raise ValueError("ID token has no subject")
        return claims

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        grant = self._unsign("code", authorization_code)
        if grant is None or grant["client"] != self._client_ref(client.client_id):
            return None
        if grant["jti"] in self._used_codes:
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=grant["scopes"],
            expires_at=grant["exp"],
            client_id=client.client_id,
            code_challenge=grant["challenge"],
            redirect_uri=grant["redirect_uri"],
            redirect_uri_provided_explicitly=grant["explicit"],
            resource=grant["resource"],
            subject=grant["sub"],
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        now = time.time()
        self._used_codes = {jti: exp for jti, exp in self._used_codes.items() if exp > now}
        self._used_codes[self._unsign("code", authorization_code.code)["jti"]] = authorization_code.expires_at
        return self._issue_tokens(
            client, authorization_code.scopes, authorization_code.resource, authorization_code.subject
        )

    # --- tokens ------------------------------------------------------------

    def _issue_tokens(
        self, client: OAuthClientInformationFull, scopes: list[str], resource: str | None, subject: str | None
    ) -> OAuthToken:
        now = int(time.time())
        grant = {"client": self._client_ref(client.client_id), "scopes": scopes, "resource": resource, "sub": subject}
        return OAuthToken(
            access_token=self._sign("access", {**grant, "exp": now + ACCESS_TOKEN_TTL}),
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            refresh_token=self._sign("refresh", {**grant, "exp": now + REFRESH_TOKEN_TTL}),
            scope=" ".join(scopes) or None,
        )

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        grant = self._unsign("refresh", refresh_token)
        if grant is None or grant["client"] != self._client_ref(client.client_id):
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=grant["scopes"],
            expires_at=grant["exp"],
            resource=grant["resource"],
            subject=grant["sub"],
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        return self._issue_tokens(client, scopes or refresh_token.scopes, refresh_token.resource, refresh_token.subject)

    async def load_access_token(self, token: str) -> AccessToken | None:
        if self.static_token and hmac.compare_digest(token.encode(), self.static_token.encode()):
            return AccessToken(token=token, client_id="static-token", scopes=[])
        grant = self._unsign("access", token)
        if grant is None:
            return None
        return AccessToken(
            token=token,
            client_id=grant["client"],
            scopes=grant["scopes"],
            expires_at=grant["exp"],
            resource=grant["resource"],
            subject=grant["sub"],
            claims={"iss": self.public_url},
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        # Stateless tokens can't be revoked early (see module docstring); the
        # revocation endpoint is not advertised.
        return None
