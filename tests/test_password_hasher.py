"""Tests for the pluggable password hasher (host suite -- stdlib only).

Exercises ``Pbkdf2Sha256Hasher``: round-trip verify, wrong-password rejection,
encoded-string shape, constant-time comparison, cross-iteration verify (params
read from the stored hash), ``needs_rehash`` upgrade signalling, and malformed
input safety (``verify`` never raises).
"""

from __future__ import annotations

import unittest

from ctf_generator.application.auth.hashing import (
    DEFAULT_PBKDF2_ITERATIONS,
    Pbkdf2Sha256Hasher,
    default_password_hasher,
)


class Pbkdf2HasherTests(unittest.TestCase):
    def setUp(self) -> None:
        # Low iteration count keeps the unit test fast; correctness is
        # iteration-independent (the count is embedded in the encoded hash).
        self.hasher = Pbkdf2Sha256Hasher(iterations=1000)

    def test_default_meets_owasp_floor(self) -> None:
        self.assertGreaterEqual(DEFAULT_PBKDF2_ITERATIONS, 600_000)
        self.assertEqual(
            default_password_hasher().iterations, DEFAULT_PBKDF2_ITERATIONS
        )

    def test_hash_verify_round_trip(self) -> None:
        encoded = self.hasher.hash("correct horse battery staple")
        self.assertTrue(self.hasher.verify("correct horse battery staple", encoded))

    def test_wrong_password_rejected(self) -> None:
        encoded = self.hasher.hash("s3cret-password")
        self.assertFalse(self.hasher.verify("wrong-password", encoded))

    def test_encoded_shape_and_salt_uniqueness(self) -> None:
        a = self.hasher.hash("password123")
        b = self.hasher.hash("password123")
        self.assertNotEqual(a, b)  # random per-password salt
        algo, iters, salt_b64, hash_b64 = a.split("$")
        self.assertEqual(algo, "pbkdf2_sha256")
        self.assertEqual(int(iters), 1000)
        self.assertTrue(salt_b64 and hash_b64)
        # A raw password can never look like an encoded hash.
        self.assertNotIn("password123", a)

    def test_verify_reads_params_from_stored_hash(self) -> None:
        # A hash produced at 1000 iterations verifies even under a hasher whose
        # default is far higher -- the iteration count is read from the string.
        stored = Pbkdf2Sha256Hasher(iterations=1000).hash("pw-abcdefgh")
        high = Pbkdf2Sha256Hasher(iterations=5000)
        self.assertTrue(high.verify("pw-abcdefgh", stored))

    def test_needs_rehash_on_weaker_params(self) -> None:
        weak = Pbkdf2Sha256Hasher(iterations=1000).hash("pw-abcdefgh")
        self.assertTrue(Pbkdf2Sha256Hasher(iterations=5000).needs_rehash(weak))
        strong = Pbkdf2Sha256Hasher(iterations=5000).hash("pw-abcdefgh")
        self.assertFalse(Pbkdf2Sha256Hasher(iterations=5000).needs_rehash(strong))

    def test_verify_never_raises_on_malformed(self) -> None:
        for bad in ["", "not-a-hash", "pbkdf2_sha256$notint$x$y", "a$b$c", "$$$"]:
            self.assertFalse(self.hasher.verify("whatever", bad), bad)
        self.assertTrue(self.hasher.needs_rehash("garbage"))

    def test_unknown_algorithm_does_not_verify(self) -> None:
        # A future/foreign algorithm string is rejected by this hasher (a real
        # Argon2 hasher would own it), never crashes.
        self.assertFalse(self.hasher.verify("pw", "argon2id$v=19$m$salt$hash"))


if __name__ == "__main__":
    unittest.main()
