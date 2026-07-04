"""Admin dashboard + public scoreboard: session login with token rotation.

Stdlib-only (``http.server``/``hmac``/``hashlib``/``secrets``/``pbkdf2``), no
Flask/FastAPI. Every external effect -- the wall clock and session/CSRF token
generation -- sits behind an injected callable so the whole HTTP surface is
testable by calling :func:`dispatch` directly with fakes; no real sockets are
opened in tests.

Two independent trust boundaries share this module:

* **Admin** routes (``/``, ``/api/*``) require a valid, non-expired session
  cookie established by ``POST /login``. Every authenticated request rotates
  the session token (the old token stops working immediately after), and
  every ``POST`` additionally requires a matching CSRF token header.
* **Public** routes (``/public/*``) require only a static, distinct
  "public scoreboard token" -- never the admin session -- and expose nothing
  but the already-redacted ``CompetitionService.public_leaderboard()`` view
  plus a redacted feed. This is the URL an admin can hand out/publish without
  handing out the dashboard.

:func:`serve` is a thin, intentionally untested adapter that wires
``http.server.ThreadingHTTPServer`` up to :func:`dispatch` for real use.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Protocol
from urllib.parse import parse_qsl, urlsplit

from . import dashboard_ui
from .competition_service import CompetitionService

# --- Wire types --------------------------------------------------------------


@dataclass
class DashboardRequest:
    """A transport-agnostic HTTP request. Built by :func:`serve`'s adapter
    for real traffic, or constructed directly by tests."""

    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def header(self, name: str) -> str | None:
        target = name.lower()
        for key, value in self.headers.items():
            if key.lower() == target:
                return value
        return None


@dataclass
class DashboardResponse:
    status: int
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


SESSION_COOKIE = "ctfgen_session"
CSRF_HEADER = "X-CSRF-Token"
PUBLIC_TOKEN_HEADER = "X-Public-Token"
PUBLIC_TOKEN_QUERY = "token"


def _json_response(status: int, payload: object, cookies: dict[str, str] | None = None) -> DashboardResponse:
    return DashboardResponse(
        status=status,
        body=json.dumps(payload, sort_keys=True),
        headers={"Content-Type": "application/json"},
        cookies=dict(cookies) if cookies else {},
    )


def _error(status: int, message: str) -> DashboardResponse:
    return _json_response(status, {"error": message})


# --- Auth config (admin credentials) ------------------------------------------


@dataclass(frozen=True)
class AuthConfig:
    """Admin credentials (PBKDF2-hashed) + session policy + the distinct
    public scoreboard token.

    Construct via :meth:`create` (which hashes a plaintext password); the raw
    ``password_hash``/``password_salt`` fields exist so a config can be
    reconstructed from persisted values without ever storing the plaintext.
    """

    admin_username: str
    password_hash: bytes
    password_salt: bytes
    public_token: str
    session_ttl_seconds: int = 900
    # OWASP Password Storage Cheat Sheet (2023) minimum for PBKDF2-HMAC-SHA256.
    pbkdf2_iterations: int = 600_000
    # Multi-admin roster: an immutable tuple of ``(username, hash, salt)``
    # triples (empty for a single-admin config built via :meth:`create`, in
    # which case only the top-level ``admin_username``/``password_*`` fields
    # apply -- back-compat). Populated by :meth:`from_users`.
    admins: tuple[tuple[str, bytes, bytes], ...] = ()

    @classmethod
    def create(
        cls,
        admin_username: str,
        password: str,
        *,
        public_token: str | None = None,
        session_ttl_seconds: int = 900,
        pbkdf2_iterations: int = 600_000,
        salt: bytes | None = None,
    ) -> "AuthConfig":
        salt = salt if salt is not None else secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, pbkdf2_iterations)
        return cls(
            admin_username=admin_username,
            password_hash=password_hash,
            password_salt=salt,
            public_token=public_token if public_token is not None else secrets.token_urlsafe(24),
            session_ttl_seconds=session_ttl_seconds,
            pbkdf2_iterations=pbkdf2_iterations,
        )

    def verify_password(self, username: str, password: str) -> bool:
        # Always run PBKDF2 -- even when the username does not match -- so login
        # response time is independent of whether the username exists. Bailing
        # out early on a username miss (before hashing) would turn the
        # ~PBKDF2-cost delay into a username-enumeration oracle (CWE-208). Both
        # the username and password checks use constant-time compare_digest,
        # and are evaluated fully before the ``and`` combines the results.
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.password_salt, self.pbkdf2_iterations
        )
        user_ok = secrets.compare_digest(username, self.admin_username)
        pass_ok = secrets.compare_digest(candidate, self.password_hash)
        return user_ok and pass_ok

    @classmethod
    def from_users(
        cls,
        users: "list[tuple[str, str]]",
        *,
        public_token: str | None = None,
        session_ttl_seconds: int = 900,
        pbkdf2_iterations: int = 600_000,
        salt: bytes | None = None,
    ) -> "AuthConfig":
        """Build a multi-admin config from ``(username, password)`` pairs.

        Each admin gets its own PBKDF2 hash. A per-user random salt is used
        unless ``salt`` is supplied (which pins the salt for all users, for
        deterministic tests). The first user is also mirrored into the
        back-compat top-level ``admin_username``/``password_*`` fields so a
        ``from_users`` config is a strict superset of a single-admin one.
        """
        admins: list[tuple[str, bytes, bytes]] = []
        for username, password in users:
            user_salt = salt if salt is not None else secrets.token_bytes(16)
            pwd_hash = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), user_salt, pbkdf2_iterations
            )
            admins.append((username, pwd_hash, user_salt))
        if not admins:
            raise ValueError("from_users requires at least one (username, password) pair")
        first_user, first_hash, first_salt = admins[0]
        return cls(
            admin_username=first_user,
            password_hash=first_hash,
            password_salt=first_salt,
            public_token=public_token if public_token is not None else secrets.token_urlsafe(24),
            session_ttl_seconds=session_ttl_seconds,
            pbkdf2_iterations=pbkdf2_iterations,
            admins=tuple(admins),
        )

    def verify_any(self, username: str, password: str) -> bool:
        """Validate ``(username, password)`` against any configured admin.

        Checks the multi-admin :attr:`admins` roster first, then falls back
        to the single-admin :meth:`verify_password` -- so this is correct for
        both configs built via :meth:`from_users` and via :meth:`create`.

        Every roster entry is hashed regardless of whether its username
        matches, and there is no early ``return`` on the first match, so the
        total PBKDF2 work is a function only of the roster size -- never of
        *which* (or whether any) username was supplied. This keeps login
        timing free of a username-enumeration side channel (CWE-208).
        """
        matched = False
        for admin_user, admin_hash, admin_salt in self.admins:
            candidate = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), admin_salt, self.pbkdf2_iterations
            )
            user_ok = secrets.compare_digest(username, admin_user)
            pass_ok = secrets.compare_digest(candidate, admin_hash)
            if user_ok and pass_ok:
                matched = True
        # Single-admin fallback (also constant-work) covers a create()-built
        # config and the first user mirrored into the top-level fields.
        if self.verify_password(username, password):
            matched = True
        return matched


# --- Sessions ------------------------------------------------------------------


@dataclass
class Session:
    token: str
    username: str
    issued_at: datetime
    expires_at: datetime
    csrf_token: str

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at


TokenFactory = Callable[[], str]


class SessionStore(Protocol):
    def new_token(self) -> str:
        ...

    def create(self, session: Session) -> None:
        ...

    def get(self, token: str) -> Session | None:
        ...

    def rotate(self, old_token: str, *, now: datetime, ttl_seconds: int) -> Session | None:
        """Replace ``old_token`` with a freshly-issued token for the same
        session (same username/csrf_token, new expiry), and invalidate
        ``old_token``. Returns ``None`` if ``old_token`` is not a live
        session."""
        ...

    def delete(self, token: str) -> None:
        ...


class InMemorySessionStore:
    """Volatile, process-local session store. Injectable token factory
    (defaults to ``secrets.token_urlsafe``) so tests can supply deterministic
    tokens."""

    def __init__(self, token_factory: TokenFactory | None = None) -> None:
        self._token_factory: TokenFactory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._sessions: dict[str, Session] = {}

    def new_token(self) -> str:
        return self._token_factory()

    def create(self, session: Session) -> None:
        self._sessions[session.token] = session

    def get(self, token: str) -> Session | None:
        return self._sessions.get(token)

    def rotate(self, old_token: str, *, now: datetime, ttl_seconds: int) -> Session | None:
        old = self._sessions.pop(old_token, None)
        if old is None:
            return None
        new_session = Session(
            token=self.new_token(),
            username=old.username,
            issued_at=old.issued_at,
            expires_at=now + timedelta(seconds=ttl_seconds),
            csrf_token=old.csrf_token,
        )
        self._sessions[new_session.token] = new_session
        return new_session

    def delete(self, token: str) -> None:
        self._sessions.pop(token, None)


Clock = Callable[[], datetime]


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


# --- Dispatch ------------------------------------------------------------------


def dispatch(
    request: DashboardRequest,
    *,
    service: CompetitionService,
    sessions: SessionStore,
    auth: AuthConfig,
    clock: Clock | None = None,
) -> DashboardResponse:
    """Route a single :class:`DashboardRequest` to a :class:`DashboardResponse`.

    Pure given its injected collaborators: no sockets, no wall-clock reads
    (uses ``clock`` when supplied), no direct ``secrets``/token generation
    (uses ``sessions.new_token()``).
    """
    clock = clock or _default_clock
    method = request.method.upper()
    path = request.path

    if method == "POST" and path == "/login":
        return _handle_login(request, sessions=sessions, auth=auth, clock=clock)
    if method == "POST" and path == "/logout":
        return _handle_logout(request, sessions=sessions)

    if path == "/public/scoreboard" and method == "GET":
        return _handle_public(request, service=service, auth=auth, kind="scoreboard", clock=clock)
    if path == "/public/feed" and method == "GET":
        return _handle_public(request, service=service, auth=auth, kind="feed", clock=clock)

    # --- Browser HTML routes (additive). These serve self-contained HTML
    # shells; all live data is still fetched by the page JS from the JSON
    # routes above/below. GET "/" only serves HTML when the client asks for
    # it (Accept: text/html); an API client with no such header falls
    # through to the existing JSON dashboard handler unchanged.
    if path == "/login" and method == "GET":
        return _html_response(200, dashboard_ui.login_page())
    if path == "/public" and method == "GET":
        return _handle_public_page(request, service=service, auth=auth, clock=clock)
    if path == "/" and method == "GET" and _wants_html(request):
        return _handle_dashboard_page(
            request, service=service, sessions=sessions, auth=auth, clock=clock
        )

    if path in ("/", "/api/progress", "/api/leaderboard", "/api/feed") or (
        path == "/api/event" and method == "POST"
    ):
        return _handle_admin(request, service=service, sessions=sessions, auth=auth, clock=clock)

    return _error(404, "not found")


def _handle_login(
    request: DashboardRequest, *, sessions: SessionStore, auth: AuthConfig, clock: Clock
) -> DashboardResponse:
    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return _error(400, "invalid json body")

    username = str(payload.get("username", ""))
    password = str(payload.get("password", ""))
    if not auth.verify_any(username, password):
        return _error(401, "invalid credentials")

    now = clock()
    session = Session(
        token=sessions.new_token(),
        username=username,
        issued_at=now,
        expires_at=now + timedelta(seconds=auth.session_ttl_seconds),
        csrf_token=sessions.new_token(),
    )
    sessions.create(session)
    return _json_response(
        200,
        {"ok": True, "csrf_token": session.csrf_token},
        cookies={SESSION_COOKIE: session.token},
    )


def _handle_logout(request: DashboardRequest, *, sessions: SessionStore) -> DashboardResponse:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        sessions.delete(token)
    return _json_response(200, {"ok": True}, cookies={SESSION_COOKIE: ""})


def _handle_public(
    request: DashboardRequest,
    *,
    service: CompetitionService,
    auth: AuthConfig,
    kind: str,
    clock: Clock,
) -> DashboardResponse:
    token = request.header(PUBLIC_TOKEN_HEADER) or request.query.get(PUBLIC_TOKEN_QUERY, "")
    if not token or not secrets.compare_digest(token, auth.public_token):
        return _error(401, "invalid public token")

    if kind == "scoreboard":
        return _json_response(200, {"scoreboard": service.public_leaderboard(as_of=clock())})

    since = _parse_since(request.query.get("since", "0"))
    redacted = [
        {
            "seq": event.seq,
            "ts": event.ts,
            "type": event.type,
            "display_name": service.teams.get(event.team_id, event.team_id),
        }
        for event in service.feed_since(since)
        if event.type == "solve"
    ]
    return _json_response(200, {"feed": redacted})


def _html_response(status: int, html: str, cookies: dict[str, str] | None = None) -> DashboardResponse:
    return DashboardResponse(
        status=status,
        body=html,
        headers={"Content-Type": "text/html; charset=utf-8"},
        cookies=dict(cookies) if cookies else {},
    )


def _wants_html(request: DashboardRequest) -> bool:
    """True when the client's ``Accept`` header prefers HTML (a browser)."""
    accept = (request.header("Accept") or "").lower()
    return "text/html" in accept


def _handle_public_page(
    request: DashboardRequest, *, service: CompetitionService, auth: AuthConfig, clock: Clock
) -> DashboardResponse:
    """Serve the public scoreboard HTML shell, gated on the public token
    (via ``?token=`` or the public-token header) -- never the admin session."""
    token = request.header(PUBLIC_TOKEN_HEADER) or request.query.get(PUBLIC_TOKEN_QUERY, "")
    if not token or not secrets.compare_digest(token, auth.public_token):
        return _error(401, "invalid public token")
    return _html_response(
        200, dashboard_ui.public_scoreboard_page(service.public_leaderboard(as_of=clock()))
    )


def _handle_dashboard_page(
    request: DashboardRequest,
    *,
    service: CompetitionService,
    sessions: SessionStore,
    auth: AuthConfig,
    clock: Clock,
) -> DashboardResponse:
    """Serve the admin dashboard HTML shell to an authenticated session.

    This is a read-only shell load -- it validates (but does not rotate) the
    session, so a browser refresh never invalidates a live session mid-flight.
    Unauthenticated (or public-token-as-cookie) requests are redirected to the
    login page. Live/mutating traffic still goes through the JSON handlers,
    which enforce rotation + CSRF.
    """
    token = request.cookies.get(SESSION_COOKIE)
    session = sessions.get(token) if token else None
    now = clock()
    if session is None or session.is_expired(now):
        return DashboardResponse(status=302, headers={"Location": "/login"})
    return _html_response(
        200, dashboard_ui.admin_dashboard_page(service.public_leaderboard(as_of=now))
    )


def _handle_admin(
    request: DashboardRequest,
    *,
    service: CompetitionService,
    sessions: SessionStore,
    auth: AuthConfig,
    clock: Clock,
) -> DashboardResponse:
    token = request.cookies.get(SESSION_COOKIE)
    session = sessions.get(token) if token else None
    now = clock()
    if session is None or session.is_expired(now):
        return _error(401, "unauthorized")

    method = request.method.upper()
    if method == "POST":
        csrf = request.header(CSRF_HEADER) or ""
        if not secrets.compare_digest(csrf, session.csrf_token):
            return _error(403, "invalid csrf token")

    rotated = sessions.rotate(session.token, now=now, ttl_seconds=auth.session_ttl_seconds)
    if rotated is None:
        # Session vanished between get() and rotate() (e.g. concurrent
        # logout) -- treat as unauthenticated rather than crash.
        return _error(401, "unauthorized")

    body = _route_admin_body(request, method, service=service, now=now)
    if isinstance(body, DashboardResponse):
        response = body
    else:
        status, payload = body
        response = _json_response(status, payload)
    response.cookies[SESSION_COOKIE] = rotated.token
    return response


def _route_admin_body(
    request: DashboardRequest, method: str, *, service: CompetitionService, now: datetime
) -> tuple[int, object] | DashboardResponse:
    path = request.path

    if path == "/" and method == "GET":
        progress = {
            team_id: asdict(team) for team_id, team in service.progress().items()
        }
        return 200, {
            "progress": progress,
            "leaderboard": service.leaderboard(as_of=now).to_mapping(),
        }

    if path == "/api/progress" and method == "GET":
        progress = {
            team_id: asdict(team) for team_id, team in service.progress().items()
        }
        return 200, {"progress": progress}

    if path == "/api/leaderboard" and method == "GET":
        return 200, {"leaderboard": service.leaderboard(as_of=now).to_mapping()}

    if path == "/api/feed" and method == "GET":
        since = _parse_since(request.query.get("since", "0"))
        feed = [asdict(event) for event in service.feed_since(since)]
        return 200, {"feed": feed}

    if path == "/api/event" and method == "POST":
        try:
            payload = json.loads(request.body or "{}")
        except json.JSONDecodeError:
            return 400, {"error": "invalid json body"}
        event_type = payload.get("type")
        team_id = payload.get("team_id")
        challenge_id = payload.get("challenge_id")
        if not event_type or not team_id or not challenge_id:
            return 400, {"error": "type, team_id, and challenge_id are required"}
        event = service.record_event(
            event_type, team_id, challenge_id, payload=payload.get("payload")
        )
        return 201, {"event": asdict(event)}

    return 404, {"error": "not found"}


def _parse_since(raw: str) -> int:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


# --- Thin http.server adapter (not unit-tested) ---------------------------------


def serve(
    host: str,
    port: int,
    *,
    service: CompetitionService,
    sessions: SessionStore | None = None,
    auth: AuthConfig,
    clock: Clock | None = None,
) -> ThreadingHTTPServer:
    """Build (and return, not-yet-serving-forever) a ``ThreadingHTTPServer``
    that adapts real HTTP traffic into :func:`dispatch` calls.

    Minimal by design -- all real logic lives in :func:`dispatch`, which is
    what tests exercise. Call ``.serve_forever()`` on the returned server.
    """
    sessions = sessions or InMemorySessionStore()

    class _Handler(BaseHTTPRequestHandler):
        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length).decode("utf-8") if length else ""
            split = urlsplit(self.path)
            query = {k: v for k, v in parse_qsl(split.query)}
            cookies: dict[str, str] = {}
            cookie_header = self.headers.get("Cookie", "")
            for part in cookie_header.split(";"):
                if "=" in part:
                    key, value = part.strip().split("=", 1)
                    cookies[key] = value
            headers = {key: value for key, value in self.headers.items()}

            request = DashboardRequest(
                method=self.command,
                path=split.path,
                headers=headers,
                query=query,
                cookies=cookies,
                body=body,
            )
            response = dispatch(request, service=service, sessions=sessions, auth=auth, clock=clock)

            self.send_response(response.status)
            for key, value in response.headers.items():
                self.send_header(key, value)
            for name, value in response.cookies.items():
                if value:
                    self.send_header("Set-Cookie", f"{name}={value}; Path=/; HttpOnly; SameSite=Lax")
                else:
                    self.send_header("Set-Cookie", f"{name}=; Path=/; Max-Age=0; SameSite=Lax")
            payload = response.body.encode("utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802 (http.server API)
            self._dispatch()

        def log_message(self, format: str, *args: object) -> None:  # pragma: no cover
            pass

    return ThreadingHTTPServer((host, port), _Handler)
