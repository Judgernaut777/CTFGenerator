"""The OIDC federated-login application service (M10c).

``OidcService`` implements the OpenID Connect **authorization-code + PKCE** flow
and, on success, issues a NORMAL M10a local session (via
``AuthService.issue_federated_session``) -- OIDC is a login method, never a new
bearer type. The service owns the login-transaction unit of work and the
security-critical validation; the crypto is delegated to PyJWT + ``cryptography``
(the ``[oidc]`` extra), never hand-rolled.

Two entry points:

* :meth:`build_authorization_url` -- mint state (CSRF) + nonce (replay) + PKCE
  verifier/challenge, persist a one-time-use login transaction, and return the IdP
  authorization URL to 302-redirect to.
* :meth:`handle_callback` -- CONSUME the transaction by ``state`` (rejecting
  unknown / expired / replayed state), exchange the ``code`` at the token endpoint
  with the PKCE verifier + client auth, VALIDATE the ID token (JWKS asymmetric
  signature, ``iss`` / ``aud`` / ``exp`` / ``iat`` / ``nonce``, ``email_verified``,
  domain allow-list), map/provision the local user, and issue the local session.

Secrets discipline (REQ-INV-011): the ``client_secret``, the authorization
``code``, and the raw ID token are never logged or returned; every failure is a
single generic :class:`OidcAuthError` (401) leaking nothing about which check
failed. This module logs nothing.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlencode

import httpx

from ctf_generator.domain.auth.models import IssuedSession, OidcLoginTransaction
from ctf_generator.domain.identity.models import User
from ctf_generator.infrastructure.database.auth_repository import (
    SqlAlchemyOidcLoginTransactionRepository,
)
from ctf_generator.infrastructure.database.session import Database

from ..service import AuthService
from . import pkce
from .config import OidcProviderConfig
from .discovery import _HTTP_TIMEOUT, DiscoveryCache, DiscoveryDocument
from .errors import OidcAuthError


@dataclass(frozen=True)
class AuthorizationRedirect:
    """The result of :meth:`OidcService.build_authorization_url`: the IdP URL to
    redirect the browser to, the ``state`` (already embedded in the URL --
    surfaced only for logging/correlation; it is not a bearer secret), and the
    ``binding_secret`` the interface MUST set as an httpOnly cookie so the
    callback can prove the same user-agent started the flow (login-CSRF /
    fixation defense). ``binding_secret`` is ``repr``-suppressed -- it is a
    transient secret and must never be logged."""

    url: str
    state: str
    binding_secret: str = field(repr=False, default="")


def _is_true(value: object) -> bool:
    """Truthy interpretation of the ``email_verified`` claim, which some IdPs
    emit as a JSON boolean and others as the string ``"true"``."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


class OidcService:
    """OIDC authorization-code + PKCE login that issues a local M10a session."""

    def __init__(
        self,
        config: OidcProviderConfig,
        database: Database,
        auth_service: AuthService,
        *,
        identity_service=None,
        http_client: httpx.Client | None = None,
        discovery_cache: DiscoveryCache | None = None,
    ) -> None:
        self._config = config
        self._database = database
        self._auth = auth_service
        # IdentityService is imported lazily to avoid a hard import cycle and to
        # keep this module importable with only the auth deps.
        if identity_service is None:
            from ctf_generator.application.identity import IdentityService

            identity_service = IdentityService(database)
        self._identity = identity_service
        self._owns_http = http_client is None
        self._http = http_client or httpx.Client(timeout=_HTTP_TIMEOUT)
        self._discovery = discovery_cache or DiscoveryCache()

    @property
    def config(self) -> OidcProviderConfig:
        return self._config

    def close(self) -> None:
        """Close the owned httpx client (a no-op for an injected one)."""
        if self._owns_http:
            self._http.close()

    # -- login (build the authorization redirect) ----------------------------

    def build_authorization_url(self, now: datetime) -> AuthorizationRedirect:
        """Mint state/nonce/PKCE, persist a one-time-use login transaction, and
        return the IdP authorization URL (response_type=code, scope, redirect_uri,
        state, nonce, code_challenge + S256)."""
        doc = self._discovery.get(self._config, self._http, now)
        state = pkce.generate_state()
        nonce = pkce.generate_nonce()
        code_verifier = pkce.generate_code_verifier()
        code_challenge = pkce.code_challenge_s256(code_verifier)
        # Browser-binding secret: returned to the interface to set as a cookie;
        # only its hash is persisted (the raw secret lives only in the browser).
        binding_secret = pkce.generate_binding_secret()

        transaction = OidcLoginTransaction(
            state_hash=pkce.hash_state(state),
            nonce=nonce,
            code_verifier=code_verifier,
            binding_hash=pkce.hash_binding(binding_secret),
            redirect_uri=self._config.redirect_uri,
            created_at=now,
            expires_at=now + self._config.transaction_ttl,
        )
        with self._database.session_scope() as session:
            repo = SqlAlchemyOidcLoginTransactionRepository(session)
            repo.prune_expired(now)
            repo.add(transaction)

        params = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": self._config.redirect_uri,
            "scope": self._config.scope_param,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        url = f"{doc.authorization_endpoint}?{urlencode(params)}"
        return AuthorizationRedirect(
            url=url, state=state, binding_secret=binding_secret
        )

    # -- callback (validate + issue the local session) -----------------------

    def handle_callback(
        self,
        code: str | None,
        state: str | None,
        binding_secret: str | None,
        now: datetime,
    ) -> IssuedSession:
        """Validate the authorization-code callback and issue a local session.

        ``binding_secret`` is the value of the login cookie set at
        :meth:`build_authorization_url`; it MUST hash to the transaction's stored
        binding (proving the same user-agent started the flow -- login-CSRF /
        fixation defense).

        A missing ``code`` / ``state`` is a malformed request (:class:`ValueError`
        -> 400); every other failure (bad/expired/replayed state, missing/wrong
        binding cookie, token-exchange failure, invalid ID token, disallowed
        email) is a generic :class:`OidcAuthError` (-> 401)."""
        if not code or not state:
            raise ValueError("missing code or state parameter")

        # CONSUME the transaction by state (one-time-use + CSRF + expiry).
        with self._database.session_scope() as session:
            transaction = SqlAlchemyOidcLoginTransactionRepository(session).consume(
                pkce.hash_state(state), now
            )
        if transaction is None:
            raise OidcAuthError("unknown, expired, or replayed login state")

        # FAIL CLOSED on the browser binding: the login cookie's hash must match
        # the value stored when the flow started, so a valid (state, code) alone
        # -- without the initiating browser's cookie -- cannot complete the login
        # (login-CSRF / session fixation). The transaction is already consumed,
        # so a wrong-binding attempt cannot be retried.
        if not binding_secret or not secrets.compare_digest(
            pkce.hash_binding(binding_secret), transaction.binding_hash
        ):
            raise OidcAuthError("oidc login binding mismatch")

        doc = self._discovery.get(self._config, self._http, now)
        id_token = self._exchange_code(doc, code, transaction.code_verifier)
        claims = self._verify_id_token(doc, id_token, transaction.nonce, now)
        email = self._verified_email(claims)
        self._provision_if_needed(email, claims)
        return self._auth.issue_federated_session(email, now)

    # -- internals -----------------------------------------------------------

    def _exchange_code(
        self, doc: DiscoveryDocument, code: str, code_verifier: str
    ) -> str:
        """Exchange the authorization code for tokens at the token endpoint, with
        the PKCE ``code_verifier`` + ``client_secret_basic`` auth and an
        exact-match ``redirect_uri``. Returns the raw ``id_token``. A non-2xx or a
        missing id_token is a generic failure (never echoes the code/secret)."""
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._config.redirect_uri,
            "client_id": self._config.client_id,
            "code_verifier": code_verifier,
        }
        try:
            response = self._http.post(
                doc.token_endpoint,
                data=data,
                auth=(self._config.client_id, self._config.client_secret),
                headers={"Accept": "application/json"},
                timeout=_HTTP_TIMEOUT,
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise OidcAuthError("oidc token exchange failed") from exc

        id_token = payload.get("id_token") if isinstance(payload, dict) else None
        if not isinstance(id_token, str) or not id_token:
            raise OidcAuthError("oidc token response has no id_token")
        return id_token

    def _verify_id_token(
        self,
        doc: DiscoveryDocument,
        id_token: str,
        expected_nonce: str,
        now: datetime,
    ) -> dict:
        """Verify the ID token: asymmetric JWKS signature (RS*/ES* only -- rejects
        ``alg:none`` and HS* key-confusion), ``iss`` == configured issuer, ``aud``
        == client_id, ``exp`` / ``iat`` (with leeway), and ``nonce`` == the
        transaction's nonce. Any failure -> generic :class:`OidcAuthError`."""
        import jwt

        signing_key = self._select_signing_key(doc, id_token)
        try:
            claims = jwt.decode(
                id_token,
                key=signing_key,
                algorithms=list(self._config.allowed_algorithms),
                audience=self._config.client_id,
                issuer=self._config.issuer,
                leeway=self._config.leeway.total_seconds(),
                options={
                    "require": ["exp", "iat", "iss", "aud"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except jwt.InvalidTokenError as exc:
            raise OidcAuthError("id token validation failed") from exc

        # OIDC Core 3.1.3.7: PyJWT only checks ``client_id in aud``. When the ID
        # token has MULTIPLE audiences (or carries an ``azp``), the authorized
        # party MUST be our client_id -- otherwise a token minted for a different
        # relying party (co-audienced with us) would be accepted.
        aud = claims.get("aud")
        azp = claims.get("azp")
        if (isinstance(aud, list) and len(aud) > 1) or azp is not None:
            if azp != self._config.client_id:
                raise OidcAuthError("id token azp does not match client_id")

        # PyJWT does not validate the OIDC ``nonce`` -- bind it here.
        if not expected_nonce or claims.get("nonce") != expected_nonce:
            raise OidcAuthError("id token nonce mismatch")
        return claims

    def _select_signing_key(self, doc: DiscoveryDocument, id_token: str):
        """Fetch the JWKS (over the same http client) and select the signing key
        by the token's ``kid``. Never trusts the token's ``alg`` for key type --
        the asymmetric-only allow-list is enforced by ``jwt.decode``."""
        import jwt

        try:
            response = self._http.get(doc.jwks_uri, timeout=_HTTP_TIMEOUT)
            response.raise_for_status()
            jwks_data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise OidcAuthError("oidc jwks fetch failed") from exc

        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.InvalidTokenError as exc:
            raise OidcAuthError("malformed id token header") from exc

        try:
            jwk_set = jwt.PyJWKSet.from_dict(jwks_data)
        except (jwt.InvalidKeyError, jwt.PyJWKError, KeyError, TypeError) as exc:
            raise OidcAuthError("invalid jwks") from exc

        keys = jwk_set.keys
        if not keys:
            raise OidcAuthError("jwks has no usable keys")

        kid = header.get("kid")
        if kid is not None:
            for jwk in keys:
                if jwk.key_id == kid:
                    return jwk.key
            raise OidcAuthError("no jwks key matches the token kid")
        if len(keys) == 1:
            return keys[0].key
        raise OidcAuthError("ambiguous jwks key selection (token has no kid)")

    def _verified_email(self, claims: dict) -> str:
        """Extract the verified email from the claims. Requires an email and a
        PRESENT, truthy ``email_verified``; applies the domain allow-list."""
        email = claims.get("email")
        if not isinstance(email, str) or "@" not in email:
            raise OidcAuthError("id token carries no usable email")
        # FAIL CLOSED: email is the identity join key (auto-provision + domain
        # allow-list), so ``email_verified`` must be PRESENT and truthy. An
        # absent claim is treated as unverified -- an IdP that emits an email
        # without asserting verification must never authenticate that identity.
        if not _is_true(claims.get("email_verified")):
            raise OidcAuthError("id token email is not verified")
        if not self._config.domain_allowed(email):
            raise OidcAuthError("email domain is not allowed")
        return email

    def _provision_if_needed(self, email: str, claims: dict) -> None:
        """Map the verified email to a local user, provisioning one (with NO
        system role and NO membership -- least privilege) iff ``auto_provision``
        is enabled. An unknown email with provisioning disabled is rejected."""
        from sqlalchemy.exc import IntegrityError

        if self._identity.get(email) is not None:
            return
        if not self._config.auto_provision:
            raise OidcAuthError("no local account for this identity")
        display_name = (
            claims.get("name")
            or claims.get("preferred_username")
            or email.split("@", 1)[0]
        )
        try:
            self._identity.register(User(email=email, display_name=str(display_name)))
        except IntegrityError:
            # A concurrent provision won the race; the user now exists -- fine.
            if self._identity.get(email) is None:  # pragma: no cover - defensive
                raise OidcAuthError("provisioning failed") from None
        except ValueError as exc:
            # The IdP email is not a valid local user key.
            raise OidcAuthError("identity is not provisionable") from exc
