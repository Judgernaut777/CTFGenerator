"""``ApiClient`` -- the platform CLI's HTTP client over the supported API.

The supported CLI talks to the PLATFORM HTTP API (``/api/v1``) with a session
bearer token; it does NOT touch the database. This client:

* prefixes ``/api/v1`` and attaches ``Authorization: Bearer <token>`` from the
  :class:`~.config.TokenStore` (or an explicit CI override) on authed requests;
* parses the ``ctfgen.error`` envelope on a non-2xx response into a typed
  :class:`~.errors.ApiError` (surfacing ``code`` + ``request_id``) and raises it;
* unwraps the resource / list response envelopes on success;
* on a 401 for an authed request backed by a STORED session, attempts EXACTLY
  ONE ``/auth/refresh``, persists the rotated token, and retries the original
  request once -- if the refresh also 401s (or the retry still 401s) it raises
  :class:`~.errors.AuthRequired` (no refresh loop);
* only ever sends the bearer to the configured origin: the injected
  :class:`httpx.Client` is bound to that origin and redirects are NOT followed,
  so the token cannot leak to a cross-origin ``Location``.

The :class:`httpx.Client` is INJECTED so tests drive it in-process over
``httpx.ASGITransport(app=create_app(...))`` or a scripted ``httpx.MockTransport``
-- no real socket is needed. The token is NEVER logged or printed here.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from .config import Session, TokenStore
from .errors import ApiError, ApiUnreachable, AuthRequired

API_V1_PREFIX = "/api/v1"
DEFAULT_TIMEOUT = 30.0


def build_http_client(api_url: str, *, timeout: float = DEFAULT_TIMEOUT) -> httpx.Client:
    """Build the production :class:`httpx.Client` bound to ``api_url``.

    Redirects are disabled so a 3xx never carries the bearer token to another
    origin. Tests bypass this and inject their own client (ASGI/MockTransport)."""
    return httpx.Client(
        base_url=api_url.rstrip("/"), timeout=timeout, follow_redirects=False
    )


class ApiClient:
    """A thin, typed HTTP client over the platform API.

    Parameters
    ----------
    http:
        An injected :class:`httpx.Client` bound to the API origin.
    store:
        The session store; the bearer token is read from (and, on refresh,
        written back to) it.
    api_url:
        The resolved API base url (recorded on the session; the ``http`` client
        is what actually routes requests).
    token_override:
        A CI escape-hatch token that bypasses the stored session. When set, the
        client authenticates with it and NEVER attempts a refresh (there is no
        stored session to rotate).
    """

    def __init__(
        self,
        http: httpx.Client,
        store: TokenStore,
        api_url: str,
        *,
        token_override: str | None = None,
    ) -> None:
        self._http = http
        self._store = store
        self._api_url = api_url
        self._token_override = token_override

    # -- public API ----------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
        headers: Mapping[str, str] | None = None,
        authed: bool = True,
        return_etag: bool = False,
    ) -> Any:
        """Send one request and return the unwrapped success body.

        Non-2xx -> a typed :class:`ApiError` (or :class:`AuthRequired` on an
        unrecoverable 401 for an authed request). A 204 / empty body -> ``None``.
        A resource envelope -> its body (schema stamp stripped); a list envelope
        -> the envelope dict unchanged (so :meth:`list` can read ``page``).

        ``headers`` are extra request headers (e.g. ``If-Match`` for an
        optimistic-concurrency PATCH); the ``Authorization`` and
        ``Idempotency-Key`` headers this client manages ALWAYS win over any
        same-named caller header, so a caller can never override the bearer.

        ``return_etag=True`` returns ``(body, etag)`` where ``etag`` is the
        response ``ETag`` header (or ``None``) -- used to read a resource's
        version before a conditional update."""
        response = self._send_with_refresh(
            method,
            path,
            json=json,
            params=params,
            idempotency_key=idempotency_key,
            headers=headers,
            authed=authed,
        )
        self._raise_for_error(response, authed=authed)
        body = _unwrap(_json_or_none(response))
        if return_etag:
            return body, response.headers.get("ETag")
        return body

    def list(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Follow ``page.next_cursor`` to collect all items of a list endpoint.

        Bounded by ``limit`` (an upper bound on the number of items returned;
        ``None`` = no cap). Each page is a fresh request; the token-refresh logic
        applies per page."""
        collected: list[dict[str, Any]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        while True:
            page_params = dict(params or {})
            if cursor is not None:
                page_params["cursor"] = cursor
            body = self.request("GET", path, params=page_params or None)
            items, cursor = _list_page(body)
            collected.extend(items)
            if limit is not None and len(collected) >= limit:
                return collected[:limit]
            if cursor is None:
                return collected
            # Terminate defensively: a buggy/hostile server that keeps returning a
            # non-null cursor (repeated, or with empty pages) must not spin the CLI
            # forever. A cursor we have already followed => stop.
            if cursor in seen_cursors:
                return collected
            seen_cursors.add(cursor)

    # -- internals -----------------------------------------------------------

    def _bearer(self) -> str | None:
        if self._token_override is not None:
            return self._token_override
        session = self._store.load()
        return session.token if session is not None else None

    def _send_with_refresh(
        self,
        method: str,
        path: str,
        *,
        json: Any,
        params: Mapping[str, Any] | None,
        idempotency_key: str | None,
        headers: Mapping[str, str] | None = None,
        authed: bool,
    ) -> httpx.Response:
        response = self._raw_send(
            method, path, json=json, params=params,
            idempotency_key=idempotency_key, headers=headers, authed=authed,
        )
        if response.status_code != 401 or not authed:
            return response
        # A 401 on an authed request. Only a STORED session can be refreshed --
        # a CI override token has no rotation partner, and an absent token means
        # the user simply is not logged in.
        if self._token_override is not None or self._bearer() is None:
            raise AuthRequired()
        if not self._try_refresh():
            raise AuthRequired()
        # Exactly one retry with the rotated token. A second 401 is a genuine
        # authorization failure for this resource -- do NOT refresh again.
        retry = self._raw_send(
            method, path, json=json, params=params,
            idempotency_key=idempotency_key, headers=headers, authed=authed,
        )
        if retry.status_code == 401:
            raise AuthRequired()
        return retry

    def _try_refresh(self) -> bool:
        """Attempt a single ``/auth/refresh``. On success persist the rotated
        token and return ``True``; on a 401 return ``False`` (the caller raises
        :class:`AuthRequired`). Any OTHER error surfaces as an :class:`ApiError`."""
        current = self._store.load()
        if current is None:  # pragma: no cover - guarded by caller
            return False
        response = self._raw_send("POST", "/auth/refresh", authed=True)
        if response.status_code == 401:
            return False
        self._raise_for_error(response, authed=False)
        body = _json_or_none(response) or {}
        token = body.get("token")
        if not token:  # pragma: no cover - contract guarantees a token on 200
            return False
        self._store.save(
            Session(
                api_url=current.api_url or self._api_url,
                token=token,
                expires_at=body.get("expires_at"),
                subject=current.subject,
            )
        )
        return True

    def _raw_send(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
        headers: Mapping[str, str] | None = None,
        authed: bool = True,
    ) -> httpx.Response:
        # Caller headers go in FIRST; the bearer + idempotency key this client
        # manages are set AFTER so a caller can never override them (a spoofed
        # Authorization header would exfiltrate/replace the session token).
        send_headers: dict[str, str] = dict(headers or {})
        if authed:
            token = self._bearer()
            if token:
                send_headers["Authorization"] = f"Bearer {token}"
        if idempotency_key:
            send_headers["Idempotency-Key"] = idempotency_key
        url = f"{API_V1_PREFIX}{path}"
        try:
            return self._http.request(
                method, url, json=json, params=params, headers=send_headers
            )
        except httpx.TransportError as exc:
            # httpx.TransportError is the base of ConnectError/ConnectTimeout AND
            # ReadTimeout/PoolTimeout (TimeoutException), NetworkError, and
            # RemoteProtocolError (a server dropping the connection mid-response) --
            # every low-level transport failure maps to a friendly ApiUnreachable,
            # never a raw traceback.
            raise ApiUnreachable(
                f"cannot reach the API at {self._api_url}"
            ) from exc

    def _raise_for_error(self, response: httpx.Response, *, authed: bool) -> None:
        if response.is_success:
            return
        code, message, request_id = _parse_error_envelope(response)
        if response.status_code == 401 and authed:
            # An authed 401 that reached here already survived the refresh path
            # in _send_with_refresh (or came from a non-refreshable context).
            raise AuthRequired()
        raise ApiError(
            code, message, status_code=response.status_code, request_id=request_id
        )


def _json_or_none(response: httpx.Response) -> Any:
    if response.status_code == 204 or not response.content:
        return None
    try:
        return response.json()
    except ValueError:  # pragma: no cover - a 2xx with a non-JSON body
        return None


def _unwrap(body: Any) -> Any:
    """Strip the resource-envelope schema stamp; pass a list envelope through
    (its ``data``/``page`` are consumed by :meth:`ApiClient.list`); return any
    non-enveloped body (e.g. the ``/auth`` payloads) unchanged."""
    if isinstance(body, dict) and "schema" in body:
        if "data" in body and "page" in body:
            return body
        return {k: v for k, v in body.items() if k not in ("schema", "schema_version")}
    return body


def _list_page(body: Any) -> tuple[list[dict[str, Any]], str | None]:
    if not isinstance(body, dict):
        return [], None
    items = body.get("data") or []
    page = body.get("page") or {}
    return list(items), page.get("next_cursor")


def _parse_error_envelope(response: httpx.Response) -> tuple[str, str, str | None]:
    """Extract ``(code, message, request_id)`` from a ``ctfgen.error`` body,
    falling back to a generic code/message for a non-JSON / non-envelope error
    (e.g. a proxy 502). The token is never part of an error body."""
    fallback = (f"http_{response.status_code}", f"HTTP {response.status_code}", None)
    body = _json_or_none(response)
    if not isinstance(body, dict):
        return fallback
    error = body.get("error")
    if not isinstance(error, dict):
        return fallback
    return (
        str(error.get("code") or fallback[0]),
        str(error.get("message") or fallback[1]),
        error.get("request_id"),
    )
