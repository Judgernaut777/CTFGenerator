"""Concrete runtime-backend adapters (M8 slice 2, WORKER-SIDE infrastructure).

This package holds the concrete implementations of the
:class:`~ctf_generator.domain.execution.runtime.RuntimeBackend` Protocol. Unlike
the rest of the control plane, code in this package legitimately drives a
container runtime, so it MAY import :mod:`subprocess`. It is only ever loaded in
a worker process -- the control plane never imports it and never mounts a
container socket (the KEY INVARIANT from ADR-001 / docs/security/runtime-isolation.md).

Nothing here touches the control-plane database, the job queue, or a
session-signing key: an adapter is a pure runtime driver behind the Protocol.
"""
