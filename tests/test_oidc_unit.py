"""Unit tests for the OIDC building blocks (M10c) -- no database required.

Covers the pure PKCE/CSRF helpers, ``OidcProviderConfig`` validation + the email
domain allow-list, and discovery fetch + the **issuer mix-up defense** (via the
pure ``fetch_discovery`` against the fake IdP). SKIPS cleanly when the ``[oidc]``
/ ``[api]`` / ``[db]`` deps are not importable (host gate), and RUNS in the
``.venv`` where ``pyjwt[crypto]`` + ``httpx`` + ``sqlalchemy`` are installed.
"""

from __future__ import annotations

import base64
import hashlib
import unittest

try:
    from fixtures.fake_idp import (
        DEFAULT_CLIENT_ID,
        DEFAULT_CLIENT_SECRET,
        DEFAULT_REDIRECT_URI,
        FakeIdp,
    )

    from ctf_generator.application.auth.oidc import (
        OidcAuthError,
        OidcConfigurationError,
        OidcProviderConfig,
        pkce,
    )
    from ctf_generator.application.auth.oidc.config import (
        ALLOWED_ID_TOKEN_ALGORITHMS,
    )
    from ctf_generator.application.auth.oidc.discovery import fetch_discovery

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - host gate without extras
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_SKIP = _IMPORT_ERROR is not None
_SKIP_REASON = f"[oidc]/[api]/[db] not importable ({_IMPORT_ERROR})"


def _config(**overrides):
    base = dict(
        issuer="https://idp.example.test",
        client_id=DEFAULT_CLIENT_ID,
        client_secret=DEFAULT_CLIENT_SECRET,
        redirect_uri=DEFAULT_REDIRECT_URI,
    )
    base.update(overrides)
    return OidcProviderConfig(**base)


@unittest.skipIf(_SKIP, _SKIP_REASON)
class PkceHelperTests(unittest.TestCase):
    def test_state_and_nonce_are_high_entropy_and_unique(self) -> None:
        states = {pkce.generate_state() for _ in range(50)}
        self.assertEqual(len(states), 50)  # no collisions
        # token_urlsafe(32) -> >=43 chars of base64url == >=256 bits.
        self.assertGreaterEqual(len(pkce.generate_state()), 43)
        self.assertGreaterEqual(len(pkce.generate_nonce()), 43)

    def test_code_verifier_within_rfc7636_range(self) -> None:
        verifier = pkce.generate_code_verifier()
        self.assertTrue(43 <= len(verifier) <= 128)

    def test_s256_challenge_matches_manual_computation(self) -> None:
        verifier = "test-verifier-abc123"
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        self.assertEqual(pkce.code_challenge_s256(verifier), expected)
        self.assertNotIn("=", pkce.code_challenge_s256(verifier))  # unpadded

    def test_hash_state_is_sha256_hex(self) -> None:
        state = "some-state"
        self.assertEqual(
            pkce.hash_state(state), hashlib.sha256(state.encode()).hexdigest()
        )
        self.assertEqual(len(pkce.hash_state(state)), 64)


@unittest.skipIf(_SKIP, _SKIP_REASON)
class ConfigTests(unittest.TestCase):
    def test_scopes_always_include_openid_and_email(self) -> None:
        cfg = _config(scopes=("profile",))
        self.assertIn("openid", cfg.scopes)
        self.assertIn("email", cfg.scopes)

    def test_issuer_trailing_slash_normalized(self) -> None:
        cfg = _config(issuer="https://idp.example.test/")
        self.assertEqual(cfg.issuer, "https://idp.example.test")
        self.assertTrue(cfg.discovery_url.endswith("/.well-known/openid-configuration"))

    def test_client_secret_not_in_repr(self) -> None:
        cfg = _config(client_secret="super-secret-value")  # noqa: S106
        self.assertNotIn("super-secret-value", repr(cfg))

    def test_missing_client_secret_rejected(self) -> None:
        with self.assertRaises(OidcConfigurationError):
            _config(client_secret="")

    def test_non_https_issuer_rejected(self) -> None:
        with self.assertRaises(OidcConfigurationError):
            _config(issuer="idp.example.test")

    def test_plaintext_http_issuer_rejected(self) -> None:
        # A non-localhost http:// issuer would fetch discovery + JWKS in cleartext.
        with self.assertRaises(OidcConfigurationError):
            _config(issuer="http://idp.example.test")

    def test_https_issuer_accepted(self) -> None:
        cfg = _config(issuer="https://idp.example.test")
        self.assertEqual(cfg.issuer, "https://idp.example.test")

    def test_http_localhost_issuer_allowed_for_local_idp(self) -> None:
        # Explicit loopback exception for local / test IdPs (never leaves host).
        for issuer in (
            "http://localhost:8080",
            "http://127.0.0.1:9000",
        ):
            cfg = _config(issuer=issuer)
            self.assertEqual(cfg.issuer, issuer)

    def test_symmetric_alg_in_allowlist_rejected(self) -> None:
        with self.assertRaises(OidcConfigurationError):
            _config(allowed_algorithms=("RS256", "HS256"))
        with self.assertRaises(OidcConfigurationError):
            _config(allowed_algorithms=("none",))

    def test_default_algorithms_are_asymmetric_only(self) -> None:
        for alg in ALLOWED_ID_TOKEN_ALGORITHMS:
            self.assertFalse(alg.upper().startswith("HS"))
            self.assertNotEqual(alg.lower(), "none")

    def test_domain_allow_list(self) -> None:
        cfg = _config(allowed_domains=("example.com", "corp.test"))
        self.assertTrue(cfg.domain_allowed("alice@example.com"))
        self.assertTrue(cfg.domain_allowed("bob@CORP.TEST"))
        self.assertFalse(cfg.domain_allowed("eve@evil.com"))

    def test_no_allow_list_permits_any_domain(self) -> None:
        cfg = _config()
        self.assertTrue(cfg.domain_allowed("anyone@anywhere.example"))

    def test_from_env_returns_none_when_unconfigured(self) -> None:
        self.assertIsNone(OidcProviderConfig.from_env({}))
        # Partial config (missing secret) is still "not configured".
        self.assertIsNone(
            OidcProviderConfig.from_env(
                {
                    "CTFGEN_OIDC_ISSUER": "https://idp.example.test",
                    "CTFGEN_OIDC_CLIENT_ID": "cid",
                    "CTFGEN_OIDC_REDIRECT_URI": DEFAULT_REDIRECT_URI,
                }
            )
        )

    def test_from_env_builds_full_config(self) -> None:
        cfg = OidcProviderConfig.from_env(
            {
                "CTFGEN_OIDC_ISSUER": "https://idp.example.test",
                "CTFGEN_OIDC_CLIENT_ID": "cid",
                "CTFGEN_OIDC_CLIENT_SECRET": "sec",
                "CTFGEN_OIDC_REDIRECT_URI": DEFAULT_REDIRECT_URI,
                "CTFGEN_OIDC_ALLOWED_DOMAINS": "example.com, corp.test",
                "CTFGEN_OIDC_AUTO_PROVISION": "true",
            }
        )
        assert cfg is not None
        self.assertEqual(cfg.allowed_domains, ("example.com", "corp.test"))
        self.assertTrue(cfg.auto_provision)


@unittest.skipIf(_SKIP, _SKIP_REASON)
class DiscoveryTests(unittest.TestCase):
    def test_discovery_reads_endpoints(self) -> None:
        fake = FakeIdp()
        cfg = _config(issuer=fake.issuer, client_id=fake.client_id)
        with fake.client() as http:
            doc = fetch_discovery(cfg, http)
        self.assertEqual(doc.issuer, fake.issuer)
        self.assertEqual(doc.token_endpoint, fake.token_endpoint)
        self.assertEqual(doc.jwks_uri, fake.jwks_uri)

    def test_issuer_mixup_is_rejected(self) -> None:
        # The discovery document advertises a DIFFERENT issuer than configured --
        # a provider mix-up. fetch_discovery must reject it.
        fake = FakeIdp()
        fake.discovery_issuer_override = "https://evil.example.test"
        cfg = _config(issuer=fake.issuer, client_id=fake.client_id)
        with fake.client() as http:
            with self.assertRaises(OidcAuthError):
                fetch_discovery(cfg, http)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
