"""The worker-facing HTTP gateway (M9 slice d).

A SELF-CONTAINED FastAPI surface exposing the already-gated worker application
services (:class:`WorkerJobService`, :class:`WorkerInstanceService`) over HTTP so a
REMOTE worker process can drive the control plane across the network. Worker auth
is a plane DISJOINT from the human Principal auth (see :mod:`.deps`); worker
identity is derived exclusively from the scoped credential, never the request.
"""

from __future__ import annotations

from .router import router

__all__ = ["router"]
