"""Instance-lifecycle domain: the per-team, per-challenge running instance and
its runtime-side facts (endpoints, credentials, resources) plus the append-only
health-observation and audit-event streams (M8 slice 1b).

Pure stdlib value types; the concrete store, the guarded state-machine trigger,
and the reconciler all live in infrastructure/application. The state machine is
generation-fenced by construction so stale worker observations can never drive a
transition, and every state change is paired with an append-only audit event.

Security floor (mirrors the runtime seam): ``InstanceCredential.secret_ref`` and
``InstanceEndpoint`` carry contestant-facing *access* references only -- never the
flag, the private solver, or a raw secret value. These value types are persisted,
backed up, and operator-visible; they are secret-free by construction.
"""
