"""The organizer web application (M11 slice a).

A server-rendered HTML UI that runs ON the control-plane process and consumes the
SAME application services + M10 sessions as the JSON API -- but on a DIFFERENT
auth surface (an httpOnly cookie, not a Bearer header). It is a self-contained
sub-application (:func:`create_web_app`) that a deployment can either MOUNT on the
main API app under ``/app`` (:func:`mount_web_app`) or serve on its own listener.

Security posture (this slice):

* Cookie-session bridge over the EXACT M10 session model (no fork, no rotation on
  read -- the prototype's per-GET rotation self-DoS is deliberately not repeated).
* A strict, per-response-nonce Content-Security-Policy plus nosniff / frame-deny /
  referrer-policy on every HTML response, all assets inlined (no CDN).
* Signed, session-bound CSRF tokens on every state-changing POST.
* Jinja2 autoescape ON; NO secret (flag / token / hash / credential) is ever
  placed in a template context (REQ-INV-011).
* The SAME M10b authorization as the API: an organizer sees only its own
  competitions; an unauthorized detail is an existence-hiding 404.

Importing this package requires the ``[web]`` extra (jinja2). The API app imports
it lazily + guarded so a deployment without jinja2 simply runs without the UI.
"""

from __future__ import annotations

from .app import create_web_app, mount_web_app

__all__ = ["create_web_app", "mount_web_app"]
