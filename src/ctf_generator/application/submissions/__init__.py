"""Submission-processing application services.

The one-transaction receive -> persist -> verify -> first-correct-solve ->
Solve+ScoreEvent -> commit-once pipeline lives in ``.service``; flag
verification policy is behind the domain ``FlagVerifier`` protocol
(``.verifier`` holds the spec-backed default, stdlib-only). No re-exports
here: ``.service`` pulls the optional ``[db]`` extra, and ``.verifier`` must
stay importable without it (the host unit suite imports it directly).
"""
