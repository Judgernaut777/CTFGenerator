"""PostgreSQL integration tests for OIDC federated login (M10c; [api]+[db]+[oidc]).

Drives the FULL authorization-code + PKCE flow against a FAKE IdP double
(``fixtures.fake_idp.FakeIdp`` -- an in-test RSA keypair serving discovery + JWKS
+ token exchange and minting signed ID tokens): the login redirect carries a
valid state/nonce/PKCE challenge, and the callback with a correctly-signed ID
token issues a NORMAL M10a local session that then authenticates ``/auth/me`` and
a protected route. Auto-provision creates the user; non-auto-provision rejects an
unknown email.

The SECURITY suite actually mounts each attack against the fake IdP and asserts a
generic rejection: tampered / ``alg:none`` / HS256-confusion / wrong-aud /
wrong-iss / expired / missing-nonce / wrong-nonce ID tokens; unknown / expired /
REPLAYED state (CSRF + one-time-use); PKCE verifier mismatch; disallowed email
domain; ``email_verified=false``; a token-exchange failure. Plus a NEVER-LOG test
(REQ-INV-011) and the OIDC-UNCONFIGURED disabled-endpoint behavior.

SKIPS cleanly without the extras / ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests .venv/bin/python -m unittest test_oidc_flow_integration
"""

from __future__ import annotations

import logging
import os
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from fastapi.testclient import TestClient
    from fixtures.fake_idp import DEFAULT_EMAIL, FakeIdp
    from sqlalchemy.engine import make_url

    from ctf_generator.application.auth import AuthService
    from ctf_generator.application.auth.hashing import Pbkdf2Sha256Hasher
    from ctf_generator.application.auth.oidc import (
        OidcAuthError,
        OidcProviderConfig,
        OidcService,
    )
    from ctf_generator.domain.identity.models import User
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.models import (
        OidcLoginTransaction as OidcTxnRow,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.user_repository import (
        SqlAlchemyUserRepository,
    )
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.db_authenticator import DbAuthenticator
    from ctf_generator.interfaces.api.settings import ApiSettings

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"[api]/[db]/[oidc] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

# Local password account used by the "OIDC unaffected" / disabled tests.
_LOCAL_EMAIL = "local@example.com"
_LOCAL_PASSWORD = "correct-horse-battery"  # noqa: S105 - test fixture


@contextmanager
def _harness(
    fake=None,
    *,
    auto_provision=False,
    allowed_domains=(),
    seed_oidc_email=None,
    seed_oidc_admin=False,
    seed_local=False,
    enable_oidc=True,
):
    """Create an isolated database, run migrations, and build an app with (or
    without) the OIDC service wired. Yields ``(client, oidc_service, database)``."""
    base = make_url(_TEST_URL)
    name = f"ctfgen_oidc_it_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        url = base.set(database=name).render_as_string(hide_password=False)
        cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
        db = Database(DatabaseConfig(url=url))
        oidc_service = None
        try:
            auth = AuthService(db, hasher=Pbkdf2Sha256Hasher(iterations=1000))
            if seed_local:
                with db.session_scope() as s:
                    SqlAlchemyUserRepository(s).add(
                        User(email=_LOCAL_EMAIL, display_name="Local")
                    )
                auth.set_password(_LOCAL_EMAIL, _LOCAL_PASSWORD, datetime.now(UTC))
            if seed_oidc_email:
                with db.session_scope() as s:
                    SqlAlchemyUserRepository(s).add(
                        User(email=seed_oidc_email, display_name="Fed")
                    )
                if seed_oidc_admin:
                    auth.grant_system_role(seed_oidc_email, "admin")
            if enable_oidc:
                assert fake is not None
                config = OidcProviderConfig(
                    issuer=fake.issuer,
                    client_id=fake.client_id,
                    client_secret=fake.client_secret,
                    redirect_uri=(
                        "https://ctfgen.example.test/api/v1/auth/oidc/callback"
                    ),
                    auto_provision=auto_provision,
                    allowed_domains=allowed_domains,
                )
                oidc_service = OidcService(
                    config, db, auth, http_client=fake.client()
                )
            app = create_app(
                ApiSettings(),
                database=db,
                auth_service=auth,
                authenticator=DbAuthenticator(auth),
                oidc_service=oidc_service,
            )
            # https base URL so the Secure browser-binding cookie set at /login
            # is carried back to /callback (an http client drops Secure cookies).
            yield TestClient(app, base_url="https://testserver"), oidc_service, db
        finally:
            if oidc_service is not None:
                oidc_service.close()
            db.dispose()
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _drive(svc, fake, now, *, id_token=None, mutate_txn=None):
    """Build the auth URL, have the fake IdP issue a code, optionally mutate the
    stored transaction, and return ``(code, state, binding)`` ready for
    handle_callback."""
    redirect = svc.build_authorization_url(now)
    ctx = fake.parse_auth(redirect.url)
    code = fake.register_code(ctx, id_token=id_token)
    if mutate_txn is not None:
        mutate_txn(ctx)
    return code, redirect.state, redirect.binding_secret


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class OidcFlowIntegrationTests(unittest.TestCase):
    def test_login_redirect_carries_state_nonce_and_pkce(self) -> None:
        fake = FakeIdp()
        with _harness(fake, seed_oidc_email=DEFAULT_EMAIL) as (client, _svc, _db):
            r = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
            self.assertEqual(r.status_code, 302, r.text)
            location = r.headers["location"]
            params = fake.parse_auth(location)
            self.assertTrue(location.startswith(fake.authorization_endpoint))
            self.assertEqual(params["response_type"], "code")
            self.assertEqual(params["code_challenge_method"], "S256")
            self.assertIn("state", params)
            self.assertIn("nonce", params)
            self.assertIn("code_challenge", params)
            self.assertIn("openid", params["scope"])
            # The PKCE challenge is the S256 of the stored verifier -- prove the
            # binding by re-deriving it from the transaction row.
            from ctf_generator.application.auth.oidc import pkce

            with _db.session_scope() as s:
                row = s.query(OidcTxnRow).one()
            self.assertEqual(
                pkce.code_challenge_s256(row.code_verifier), params["code_challenge"]
            )
            self.assertEqual(pkce.hash_state(params["state"]), row.state_hash)

    def test_full_callback_issues_local_session_authenticating_me(self) -> None:
        fake = FakeIdp()
        with _harness(fake, seed_oidc_email=DEFAULT_EMAIL) as (client, _svc, _db):
            r = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
            code = fake.authorize(r.headers["location"])
            state = fake.parse_auth(r.headers["location"])["state"]
            cb = client.get(
                "/api/v1/auth/oidc/callback",
                params={"code": code, "state": state},
            )
            self.assertEqual(cb.status_code, 200, cb.text)
            token = cb.json()["token"]
            self.assertTrue(token)
            self.assertIn("expires_at", cb.json())
            # The federated login yielded a NORMAL local session bearer.
            me = client.get(
                "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
            )
            self.assertEqual(me.status_code, 200, me.text)
            self.assertEqual(me.json()["subject"], DEFAULT_EMAIL)

    def test_session_authenticates_protected_route(self) -> None:
        fake = FakeIdp()
        with _harness(
            fake, seed_oidc_email=DEFAULT_EMAIL, seed_oidc_admin=True
        ) as (client, _svc, _db):
            r = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
            code = fake.authorize(r.headers["location"])
            state = fake.parse_auth(r.headers["location"])["state"]
            token = client.get(
                "/api/v1/auth/oidc/callback", params={"code": code, "state": state}
            ).json()["token"]
            # A system-admin-scoped protected route accepts the federated session.
            protected = client.get(
                "/api/v1/users", headers={"Authorization": f"Bearer {token}"}
            )
            self.assertEqual(protected.status_code, 200, protected.text)

    def test_auto_provision_creates_the_user(self) -> None:
        fake = FakeIdp()
        with _harness(fake, auto_provision=True) as (client, _svc, db):
            # No user seeded; auto_provision must create one on first login.
            r = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
            code = fake.authorize(r.headers["location"])
            state = fake.parse_auth(r.headers["location"])["state"]
            cb = client.get(
                "/api/v1/auth/oidc/callback", params={"code": code, "state": state}
            )
            self.assertEqual(cb.status_code, 200, cb.text)
            with db.session_scope() as s:
                self.assertIsNotNone(SqlAlchemyUserRepository(s).get(DEFAULT_EMAIL))

    def test_login_sets_binding_cookie_and_callback_succeeds(self) -> None:
        fake = FakeIdp()
        with _harness(fake, seed_oidc_email=DEFAULT_EMAIL) as (client, _svc, _db):
            r = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
            self.assertEqual(r.status_code, 302, r.text)
            set_cookie = r.headers.get("set-cookie", "")
            self.assertIn("ctfgen_oidc_txn=", set_cookie)
            self.assertIn("HttpOnly", set_cookie)
            self.assertIn("Secure", set_cookie)
            # The client carries the binding cookie back to the callback -> 200.
            code = fake.authorize(r.headers["location"])
            state = fake.parse_auth(r.headers["location"])["state"]
            cb = client.get(
                "/api/v1/auth/oidc/callback", params={"code": code, "state": state}
            )
            self.assertEqual(cb.status_code, 200, cb.text)
            self.assertTrue(cb.json()["token"])

    def test_callback_without_binding_cookie_rejected(self) -> None:
        fake = FakeIdp()
        with _harness(fake, seed_oidc_email=DEFAULT_EMAIL) as (client, _svc, _db):
            r = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
            code = fake.authorize(r.headers["location"])
            state = fake.parse_auth(r.headers["location"])["state"]
            # Drop the browser-binding cookie -> a valid (state, code) alone must
            # NOT complete the login (login-CSRF / fixation).
            client.cookies.clear()
            cb = client.get(
                "/api/v1/auth/oidc/callback", params={"code": code, "state": state}
            )
            self.assertEqual(cb.status_code, 401, cb.text)
            self.assertEqual(cb.json()["error"]["code"], "unauthorized")

    def test_callback_with_wrong_binding_cookie_rejected(self) -> None:
        fake = FakeIdp()
        with _harness(fake, seed_oidc_email=DEFAULT_EMAIL) as (client, _svc, _db):
            r = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
            code = fake.authorize(r.headers["location"])
            state = fake.parse_auth(r.headers["location"])["state"]
            # Attacker-supplied binding value -> rejected.
            client.cookies.clear()
            client.cookies.set("ctfgen_oidc_txn", "attacker-supplied-value")
            cb = client.get(
                "/api/v1/auth/oidc/callback", params={"code": code, "state": state}
            )
            self.assertEqual(cb.status_code, 401, cb.text)
            self.assertEqual(cb.json()["error"]["code"], "unauthorized")

    def test_unknown_email_without_auto_provision_is_rejected(self) -> None:
        fake = FakeIdp()
        with _harness(fake, auto_provision=False) as (client, _svc, db):
            r = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
            code = fake.authorize(r.headers["location"])
            state = fake.parse_auth(r.headers["location"])["state"]
            cb = client.get(
                "/api/v1/auth/oidc/callback", params={"code": code, "state": state}
            )
            self.assertEqual(cb.status_code, 401, cb.text)
            self.assertEqual(cb.json()["error"]["code"], "unauthorized")
            with db.session_scope() as s:
                self.assertIsNone(SqlAlchemyUserRepository(s).get(DEFAULT_EMAIL))


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class OidcSecurityTests(unittest.TestCase):
    """Each test mounts the attack against the fake IdP and asserts rejection.

    Driven at the service level (``OidcService.handle_callback``) so ``now`` and
    the minted token are fully controlled. Every rejection is an ``OidcAuthError``
    (which the API maps to a generic 401)."""

    @contextmanager
    def _svc(self, **harness_kwargs):
        fake = FakeIdp()
        with _harness(fake, seed_oidc_email=DEFAULT_EMAIL, **harness_kwargs) as (
            _client,
            svc,
            db,
        ):
            yield svc, fake, db

    def _now(self) -> datetime:
        return datetime.now(UTC)

    def test_tampered_signature_rejected(self) -> None:
        with self._svc() as (svc, fake, _db):
            now = self._now()
            red = svc.build_authorization_url(now)
            ctx = fake.parse_auth(red.url)
            tampered = fake.tamper(fake.mint_id_token(nonce=ctx["nonce"]))
            code = fake.register_code(ctx, id_token=tampered)
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(code, red.state, red.binding_secret, now)

    def test_alg_none_token_rejected(self) -> None:
        with self._svc() as (svc, fake, _db):
            now = self._now()
            red = svc.build_authorization_url(now)
            ctx = fake.parse_auth(red.url)
            code = fake.register_code(
                ctx, id_token=fake.none_token(nonce=ctx["nonce"])
            )
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(code, red.state, red.binding_secret, now)

    def test_hs256_key_confusion_rejected(self) -> None:
        with self._svc() as (svc, fake, _db):
            now = self._now()
            red = svc.build_authorization_url(now)
            ctx = fake.parse_auth(red.url)
            code = fake.register_code(
                ctx, id_token=fake.hs256_confusion_token(nonce=ctx["nonce"])
            )
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(code, red.state, red.binding_secret, now)

    def test_wrong_audience_rejected(self) -> None:
        with self._svc() as (svc, fake, _db):
            now = self._now()
            red = svc.build_authorization_url(now)
            ctx = fake.parse_auth(red.url)
            code = fake.register_code(
                ctx,
                id_token=fake.mint_id_token(nonce=ctx["nonce"], aud="some-other-client"),
            )
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(code, red.state, red.binding_secret, now)

    def test_wrong_issuer_rejected(self) -> None:
        with self._svc() as (svc, fake, _db):
            now = self._now()
            red = svc.build_authorization_url(now)
            ctx = fake.parse_auth(red.url)
            code = fake.register_code(
                ctx,
                id_token=fake.mint_id_token(
                    nonce=ctx["nonce"], iss="https://evil.example.test"
                ),
            )
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(code, red.state, red.binding_secret, now)

    def test_expired_id_token_rejected(self) -> None:
        with self._svc() as (svc, fake, _db):
            now = self._now()
            red = svc.build_authorization_url(now)
            ctx = fake.parse_auth(red.url)
            past = int(now.timestamp()) - 3600
            code = fake.register_code(
                ctx,
                id_token=fake.mint_id_token(
                    nonce=ctx["nonce"], iat=past, exp=past + 60
                ),
            )
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(code, red.state, red.binding_secret, now)

    def test_missing_nonce_rejected(self) -> None:
        with self._svc() as (svc, fake, _db):
            now = self._now()
            red = svc.build_authorization_url(now)
            ctx = fake.parse_auth(red.url)
            code = fake.register_code(
                ctx, id_token=fake.mint_id_token(omit=("nonce",))
            )
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(code, red.state, red.binding_secret, now)

    def test_wrong_nonce_replay_rejected(self) -> None:
        with self._svc() as (svc, fake, _db):
            now = self._now()
            red = svc.build_authorization_url(now)
            ctx = fake.parse_auth(red.url)
            code = fake.register_code(
                ctx, id_token=fake.mint_id_token(nonce="attacker-controlled-nonce")
            )
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(code, red.state, red.binding_secret, now)

    def test_unknown_state_rejected(self) -> None:
        with self._svc() as (svc, _fake, _db):
            # No transaction exists for this state, so the state lookup rejects
            # before the binding is ever checked (the binding value is moot here).
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(
                    "some-code", "never-issued-state", "no-binding", self._now()
                )

    def test_expired_state_rejected(self) -> None:
        with self._svc() as (svc, fake, _db):
            now = self._now()
            code, state, binding = _drive(svc, fake, now)
            # Consume far in the future -- past the transaction TTL.
            future = now + timedelta(minutes=30)
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(code, state, binding, future)

    def test_replayed_state_is_one_time_use(self) -> None:
        with self._svc() as (svc, fake, _db):
            now = self._now()
            code, state, binding = _drive(svc, fake, now)
            issued = svc.handle_callback(code, state, binding, now)
            self.assertTrue(issued.token)
            # Second use of the same state must fail (transaction consumed).
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(code, state, binding, now)

    def test_pkce_verifier_mismatch_rejected(self) -> None:
        with self._svc() as (svc, fake, db):
            now = self._now()

            def _corrupt_verifier(ctx):
                # Overwrite the stored code_verifier so it no longer hashes to the
                # code_challenge the IdP recorded -> the token endpoint's PKCE
                # check fails at exchange.
                import secrets as _secrets

                with db.session_scope() as s:
                    s.query(OidcTxnRow).update(
                        {OidcTxnRow.code_verifier: _secrets.token_urlsafe(64)}
                    )

            code, state, binding = _drive(
                svc, fake, now, mutate_txn=_corrupt_verifier
            )
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(code, state, binding, now)

    def test_disallowed_email_domain_rejected(self) -> None:
        with self._svc(allowed_domains=("corp.test",)) as (svc, fake, _db):
            now = self._now()
            red = svc.build_authorization_url(now)
            ctx = fake.parse_auth(red.url)
            # DEFAULT_EMAIL is @example.com, outside the allow-list.
            code = fake.register_code(
                ctx, id_token=fake.mint_id_token(nonce=ctx["nonce"])
            )
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(code, red.state, red.binding_secret, now)

    def test_email_not_verified_rejected(self) -> None:
        with self._svc() as (svc, fake, _db):
            now = self._now()
            red = svc.build_authorization_url(now)
            ctx = fake.parse_auth(red.url)
            code = fake.register_code(
                ctx,
                id_token=fake.mint_id_token(nonce=ctx["nonce"], email_verified=False),
            )
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(code, red.state, red.binding_secret, now)

    def test_token_exchange_failure_rejected(self) -> None:
        with self._svc() as (svc, fake, _db):
            now = self._now()
            fake.fail_token_exchange = True
            code, state, binding = _drive(svc, fake, now)
            with self.assertRaises(OidcAuthError):
                svc.handle_callback(code, state, binding, now)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class OidcNeverLogTests(unittest.TestCase):
    def test_client_secret_code_and_id_token_never_logged(self) -> None:
        # REQ-INV-011: drive login + callback with a log capture and assert the
        # client_secret, the authorization code, and the raw ID token never appear
        # in OUR application logs (audit / access / app under the ``ctfgen``
        # logger). The capture is scoped to ``ctfgen`` -- NOT root -- on purpose:
        # the authorization code necessarily travels in the callback URL query
        # (that is how the OAuth redirect works), so an HTTP CLIENT logger (here
        # httpx inside the TestClient, standing in for a browser / proxy) logs the
        # dialed URL. That transport-layer log is outside the application; what we
        # own and assert is that the app's access log records only the PATH (never
        # the query) and the audit log records only the issuer + subject.
        fake = FakeIdp()
        records: list[str] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                try:
                    records.append(record.getMessage())
                except Exception:  # pragma: no cover
                    records.append(str(record.msg))

        handler = _Capture()
        with _harness(fake, seed_oidc_email=DEFAULT_EMAIL) as (client, _svc, _db):
            captured = [
                logging.getLogger("ctfgen"),
                logging.getLogger("ctfgen.api.audit"),
                logging.getLogger("ctfgen.api.access"),
            ]
            saved = [(lg, lg.disabled, lg.level) for lg in captured]
            for lg in captured:
                lg.disabled = False
                lg.setLevel(logging.DEBUG)
                lg.addHandler(handler)
            try:
                sentinel = f"positive-control-{uuid.uuid4().hex}"
                logging.getLogger("ctfgen.api.audit").warning(sentinel)
                self.assertIn(
                    sentinel,
                    "\n".join(records),
                    "log capture is not live -- never-log assertions would be vacuous",
                )
                r = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
                params = fake.parse_auth(r.headers["location"])
                id_token = fake.mint_id_token(nonce=params["nonce"])
                code = fake.register_code(params, id_token=id_token)
                cb = client.get(
                    "/api/v1/auth/oidc/callback",
                    params={"code": code, "state": params["state"]},
                )
                self.assertEqual(cb.status_code, 200, cb.text)
                token = cb.json()["token"]
            finally:
                for lg in captured:
                    lg.removeHandler(handler)
                for lg, disabled, level in saved:
                    lg.disabled = disabled
                    lg.setLevel(level)

        blob = "\n".join(records)
        self.assertNotIn(fake.client_secret, blob)
        self.assertNotIn(code, blob)
        self.assertNotIn(id_token, blob)
        self.assertNotIn(token, blob)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class OidcDisabledTests(unittest.TestCase):
    def test_endpoints_disabled_and_local_auth_unaffected(self) -> None:
        # OIDC UNCONFIGURED: the /auth/oidc/* routes do not exist (clean 404
        # envelope, never a 500), and local password auth still works.
        with _harness(enable_oidc=False, seed_local=True) as (client, svc, _db):
            self.assertIsNone(svc)
            login = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
            self.assertEqual(login.status_code, 404, login.text)
            self.assertEqual(login.json()["error"]["code"], "not_found")
            cb = client.get(
                "/api/v1/auth/oidc/callback", params={"code": "x", "state": "y"}
            )
            self.assertEqual(cb.status_code, 404, cb.text)
            # Local auth is entirely unaffected.
            r = client.post(
                "/api/v1/auth/login",
                json={"email": _LOCAL_EMAIL, "password": _LOCAL_PASSWORD},
            )
            self.assertEqual(r.status_code, 200, r.text)
            self.assertTrue(r.json()["token"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
