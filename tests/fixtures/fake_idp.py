"""A fake OpenID Connect IdP double for the M10c federated-login tests.

Generates an RSA keypair in-process and serves -- over an ``httpx.MockTransport``
routed into the real :class:`OidcService` -- the three IdP HTTP surfaces the
authorization-code flow touches:

* ``GET  <issuer>/.well-known/openid-configuration`` -- discovery metadata.
* ``GET  <jwks_uri>``                                -- the JWKS (public key).
* ``POST <token_endpoint>``                          -- the code->token exchange,
  which enforces PKCE S256 and the exact ``redirect_uri`` exactly as a real IdP
  does, and returns a pre-registered (test-minted) ID token for the code.

It MINTS signed ID tokens with configurable claims (and the attacker variants:
``alg:none``, HS256 key-confusion, tampered signature, wrong iss/aud, expired,
bad/missing nonce) so the security tests can drive real rejections against the
real service. This is a TEST DOUBLE -- the "secrets" here are fixtures.

Requires the ``[oidc]`` extra (PyJWT + cryptography); importing it without the
extra raises, and the tests skip on that.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from urllib.parse import parse_qs, parse_qsl, urlparse

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

DEFAULT_CLIENT_ID = "ctfgen-test-client"
DEFAULT_CLIENT_SECRET = "test-oidc-client-secret-should-never-leak"  # noqa: S105
DEFAULT_REDIRECT_URI = "https://ctfgen.example.test/api/v1/auth/oidc/callback"
DEFAULT_EMAIL = "federated@example.com"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _s256(verifier: str) -> str:
    import hashlib

    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


class FakeIdp:
    """An in-test OIDC provider serving discovery + JWKS + token exchange."""

    def __init__(
        self,
        issuer: str = "https://idp.example.test",
        client_id: str = DEFAULT_CLIENT_ID,
        client_secret: str = DEFAULT_CLIENT_SECRET,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.kid = "test-key-1"
        self._private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self._public = self._private.public_key()
        self.authorization_endpoint = f"{self.issuer}/authorize"
        self.token_endpoint = f"{self.issuer}/token"
        self.jwks_uri = f"{self.issuer}/jwks"
        # code -> {"id_token", "code_challenge", "redirect_uri"}
        self._codes: dict[str, dict[str, str]] = {}
        # Test knobs.
        self.discovery_issuer_override: str | None = None
        self.fail_token_exchange = False

    # -- key material --------------------------------------------------------

    def _public_pem(self) -> bytes:
        return self._public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def jwks(self) -> dict:
        jwk = json.loads(RSAAlgorithm.to_jwk(self._public))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def discovery(self) -> dict:
        return {
            "issuer": self.discovery_issuer_override or self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "jwks_uri": self.jwks_uri,
        }

    # -- ID-token minting ----------------------------------------------------

    def _default_claims(self, now: int | None = None) -> dict:
        now = now if now is not None else int(time.time())
        return {
            "iss": self.issuer,
            "sub": "idp-user-123",
            "aud": self.client_id,
            "exp": now + 300,
            "iat": now,
            "email": DEFAULT_EMAIL,
            "email_verified": True,
            "name": "Federated User",
        }

    def mint_id_token(self, *, omit: tuple[str, ...] = (), **overrides) -> str:
        """A validly RS256-signed ID token; ``**overrides`` replaces claims and
        ``omit`` drops them (e.g. ``omit=("nonce",)``)."""
        claims = self._default_claims()
        claims.update(overrides)
        for key in omit:
            claims.pop(key, None)
        return jwt.encode(
            claims, self._private, algorithm="RS256", headers={"kid": self.kid}
        )

    def none_token(self, **overrides) -> str:
        """An UNSIGNED ``alg:none`` token (the classic downgrade attack)."""
        header = {"alg": "none", "typ": "JWT", "kid": self.kid}
        claims = self._default_claims()
        claims.update(overrides)
        return (
            f"{_b64url(json.dumps(header).encode())}."
            f"{_b64url(json.dumps(claims).encode())}."
        )

    def hs256_confusion_token(self, **overrides) -> str:
        """An HS256 token forged with the RSA PUBLIC key (PEM) as the HMAC secret
        -- the classic algorithm-confusion attack an asymmetric-only verifier must
        reject. Hand-crafted because current PyJWT refuses to ``encode`` an HMAC
        with an asymmetric key (the very confusion it guards against); the point
        here is that OUR verifier rejects ``alg:HS256`` outright."""
        import hashlib
        import hmac

        header = {"alg": "HS256", "typ": "JWT", "kid": self.kid}
        claims = self._default_claims()
        claims.update(overrides)
        signing_input = (
            f"{_b64url(json.dumps(header).encode())}."
            f"{_b64url(json.dumps(claims).encode())}"
        )
        signature = hmac.new(
            self._public_pem(), signing_input.encode("ascii"), hashlib.sha256
        ).digest()
        return f"{signing_input}.{_b64url(signature)}"

    @staticmethod
    def tamper(token: str) -> str:
        """Flip the last signature character so the signature no longer verifies."""
        last = token[-1]
        return token[:-1] + ("A" if last != "A" else "B")

    # -- authorization-request handling (simulates the browser round trip) ---

    def parse_auth(self, authorization_url: str) -> dict[str, str]:
        """Parse the parameters the service put in the authorization redirect."""
        query = parse_qs(urlparse(authorization_url).query)
        return {k: v[0] for k, v in query.items()}

    def register_code(
        self, ctx: dict[str, str], *, id_token: str | None = None
    ) -> str:
        """Issue an authorization ``code`` for a parsed auth request, recording
        the PKCE ``code_challenge`` + ``redirect_uri`` (enforced at token time).
        Defaults to a valid ID token minted with the request's ``nonce``."""
        code = secrets.token_urlsafe(16)
        if id_token is None:
            id_token = self.mint_id_token(nonce=ctx.get("nonce"))
        self._codes[code] = {
            "id_token": id_token,
            "code_challenge": ctx.get("code_challenge", ""),
            "redirect_uri": ctx.get("redirect_uri", ""),
        }
        return code

    def authorize(
        self, authorization_url: str, *, id_token: str | None = None
    ) -> str:
        """Convenience: parse + register in one call. Returns the ``code``."""
        return self.register_code(self.parse_auth(authorization_url), id_token=id_token)

    # -- the MockTransport handler ------------------------------------------

    def client(self) -> httpx.Client:
        """An ``httpx.Client`` whose transport routes every request into this
        fake IdP -- injected into the OidcService as its HTTP client."""
        return httpx.Client(transport=httpx.MockTransport(self._handle))

    def _handle(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        path = request.url.path
        if request.method == "GET" and path.endswith(
            "/.well-known/openid-configuration"
        ):
            return httpx.Response(200, json=self.discovery())
        if request.method == "GET" and url == self.jwks_uri:
            return httpx.Response(200, json=self.jwks())
        if request.method == "POST" and url == self.token_endpoint:
            return self._token(request)
        return httpx.Response(404, json={"error": "not_found"})

    def _token(self, request: httpx.Request) -> httpx.Response:
        if self.fail_token_exchange:
            return httpx.Response(400, json={"error": "invalid_grant"})
        form = dict(parse_qsl(request.content.decode("utf-8")))
        code = form.get("code")
        record = self._codes.get(code or "")
        if record is None:
            return httpx.Response(400, json={"error": "invalid_grant"})
        # Exact redirect_uri match (as a real IdP enforces).
        if form.get("redirect_uri") != record["redirect_uri"]:
            return httpx.Response(400, json={"error": "invalid_grant"})
        # PKCE S256 verification: the presented verifier must hash to the
        # challenge recorded at authorization time.
        verifier = form.get("code_verifier", "")
        if not verifier or _s256(verifier) != record["code_challenge"]:
            return httpx.Response(400, json={"error": "invalid_grant"})
        # One-time code.
        self._codes.pop(code, None)
        return httpx.Response(
            200,
            json={
                "access_token": secrets.token_urlsafe(16),
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": record["id_token"],
            },
        )
