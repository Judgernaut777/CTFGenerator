"""Job-queue application services (control plane).

Pure PostgreSQL orchestration -- zero Docker imports, preserving the
control-plane-never-executes-challenge-code invariant (ADR-001). Import
``JobService`` from ``.service`` (no re-export here: the service pulls the
optional ``[db]`` extra, and this package must stay importable without it).
"""
