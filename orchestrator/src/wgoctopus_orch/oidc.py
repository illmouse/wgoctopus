"""OpenID Connect login (authorization code + PKCE) with group -> role mapping."""

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse

import httpx
import jwt

from .webauth import ROLE_RANK

ALLOWED_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"]
PENDING_TTL = 600
PENDING_MAX = 1000
DISCOVERY_TTL = 3600
JWKS_TTL = 600


class OidcError(Exception):
    """code is a short machine-readable reason; never carries tokens or claims."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Identity:
    subject: str
    username: str
    role: str


def parse_role_map(text):
    """'group-a=admin,group-b=operator' -> {'group-a': 'admin', ...}."""
    mapping = {}
    for item in (text or "").split(","):
        item = item.strip()
        if not item:
            continue
        group, sep, role = item.rpartition("=")
        group, role = group.strip(), role.strip()
        if not sep or not group or role not in ROLE_RANK:
            raise ValueError("invalid WGOCTOPUS_OIDC_ROLE_MAP entry")
        mapping[group] = role
    return mapping


def role_for_groups(groups, role_map):
    """Highest role among matching groups; None when nothing matches."""
    if isinstance(groups, str):
        groups = [groups]
    if not isinstance(groups, list):
        return None
    roles = [role_map[g] for g in groups if isinstance(g, str) and g in role_map]
    return max(roles, key=ROLE_RANK.__getitem__) if roles else None


def _challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


class OidcProvider:
    def __init__(self, settings, *, transport=None, clock=time.time):
        self.issuer = settings.oidc_issuer.rstrip("/")
        self.client_id = settings.oidc_client_id
        self.client_secret = settings.oidc_client_secret
        self.redirect_url = settings.oidc_redirect_url
        self.scopes = settings.oidc_scopes
        self.groups_claim = settings.oidc_groups_claim
        self.username_claim = settings.oidc_username_claim
        self.role_map = parse_role_map(settings.oidc_role_map)
        self._transport, self._clock = transport, clock
        self._pending = {}
        self._discovery = (0.0, None)
        self._jwks = (0.0, None)

    def _client(self):
        return httpx.AsyncClient(transport=self._transport, timeout=10, follow_redirects=False)

    def _same_origin(self, url):
        a, b = urlparse(url), urlparse(self.issuer)
        return a.scheme == b.scheme and a.scheme in ("http", "https")

    async def _discover(self):
        stamp, doc = self._discovery
        if doc is not None and self._clock() - stamp < DISCOVERY_TTL:
            return doc
        try:
            async with self._client() as client:
                resp = await client.get(f"{self.issuer}/.well-known/openid-configuration")
                resp.raise_for_status()
                doc = resp.json()
        except (httpx.HTTPError, ValueError):
            raise OidcError("discovery_failed") from None
        if (not isinstance(doc, dict) or str(doc.get("issuer", "")).rstrip("/") != self.issuer
                or not all(isinstance(doc.get(k), str) and self._same_origin(doc[k])
                           for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"))):
            raise OidcError("discovery_invalid")
        self._discovery = (self._clock(), doc)
        return doc

    async def _jwks_keys(self, force=False):
        stamp, keys = self._jwks
        if keys is not None and not force and self._clock() - stamp < JWKS_TTL:
            return keys
        doc = await self._discover()
        try:
            async with self._client() as client:
                resp = await client.get(doc["jwks_uri"])
                resp.raise_for_status()
                keys = resp.json()["keys"]
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            raise OidcError("jwks_failed") from None
        self._jwks = (self._clock(), keys)
        return keys

    def _purge(self):
        now = self._clock()
        for key in [k for k, v in self._pending.items() if v[2] <= now]:
            del self._pending[key]
        while len(self._pending) >= PENDING_MAX:
            del self._pending[next(iter(self._pending))]

    async def start(self):
        """Returns (authorization URL, state). The caller binds state to the browser."""
        doc = await self._discover()
        self._purge()
        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        self._pending[state] = (nonce, verifier, self._clock() + PENDING_TTL)
        query = urlencode({
            "response_type": "code", "client_id": self.client_id, "redirect_uri": self.redirect_url,
            "scope": self.scopes, "state": state, "nonce": nonce,
            "code_challenge": _challenge(verifier), "code_challenge_method": "S256",
        })
        return f"{doc['authorization_endpoint']}?{query}", state

    async def finish(self, code, state, browser_state):
        """Exchanges the code, verifies the ID token and maps groups to a role."""
        if not code or not state or not browser_state or not secrets.compare_digest(state, browser_state):
            raise OidcError("state_mismatch")
        self._purge()
        entry = self._pending.pop(state, None)
        if entry is None:
            raise OidcError("state_unknown")
        nonce, verifier, _ = entry
        doc = await self._discover()
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_url,
                "client_id": self.client_id, "code_verifier": verifier}
        if self.client_secret:
            data["client_secret"] = self.client_secret
        try:
            async with self._client() as client:
                resp = await client.post(doc["token_endpoint"], data=data)
                resp.raise_for_status()
                id_token = resp.json()["id_token"]
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            raise OidcError("token_exchange_failed") from None
        claims = await self._verify(id_token, nonce)
        role = role_for_groups(claims.get(self.groups_claim), self.role_map)
        subject = claims.get("sub")
        username = next((str(claims[c]).strip().lower() for c in (self.username_claim, "email", "sub")
                         if isinstance(claims.get(c), str) and claims[c].strip()), None)
        if not isinstance(subject, str) or not subject or not username or len(username) > 64:
            raise OidcError("claims_invalid")
        if role is None:
            raise OidcError("no_role")
        return Identity(subject, username, role)

    async def _verify(self, id_token, nonce):
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError:
            raise OidcError("token_invalid") from None
        if header.get("alg") not in ALLOWED_ALGS:
            raise OidcError("token_invalid")
        for force in (False, True):
            keys = await self._jwks_keys(force=force)
            jwk = next((k for k in keys if k.get("kid") == header.get("kid")), None)
            if jwk is None and not header.get("kid") and len(keys) == 1:
                jwk = keys[0]
            if jwk is not None:
                break
        else:
            raise OidcError("token_invalid")
        issuer = (await self._discover())["issuer"]
        try:
            claims = jwt.decode(id_token, key=jwt.PyJWK(jwk).key, algorithms=ALLOWED_ALGS, audience=self.client_id,
                                issuer=issuer, options={"require": ["exp", "iat", "iss", "aud", "sub"]},
                                leeway=60)
        except (jwt.PyJWTError, ValueError, TypeError):
            raise OidcError("token_invalid") from None
        if not isinstance(claims.get("nonce"), str) or not secrets.compare_digest(claims["nonce"], nonce):
            raise OidcError("nonce_mismatch")
        return claims
