"""The on-disk session store for the platform CLI (M13 slice 13a).

A single JSON file holds the current session: the API base url, the bearer
token, its expiry, and the resolved subject. Security posture (REQ-INV-011):

* The file is created ``0600`` inside a ``0700`` directory, and ``load`` REFUSES
  (warns + ignores) a file that is group/world readable, so a leaked-permission
  credential is never silently trusted.
* The token is NEVER logged or printed by this module; only ``save`` writes it
  (to the 0600 file) and ``load`` returns it in-memory to the client.

Path resolution (first match wins):

1. ``$CTFGEN_CONFIG``                        -- an explicit file path.
2. ``$XDG_CONFIG_HOME/ctfgen/credentials.json``
3. ``~/.config/ctfgen/credentials.json``
"""

from __future__ import annotations

import json
import logging
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

_logger = logging.getLogger("ctfgen.cli")

_CONFIG_ENV = "CTFGEN_CONFIG"
_XDG_ENV = "XDG_CONFIG_HOME"
_FILE_MODE = 0o600
_DIR_MODE = 0o700


def config_path() -> Path:
    """Resolve the credentials file path (see the module docstring). Does not
    touch the filesystem -- purely the resolution rule."""
    explicit = os.environ.get(_CONFIG_ENV)
    if explicit:
        return Path(explicit).expanduser()
    xdg = os.environ.get(_XDG_ENV)
    if xdg:
        return Path(xdg).expanduser() / "ctfgen" / "credentials.json"
    return Path.home() / ".config" / "ctfgen" / "credentials.json"


@dataclass(frozen=True)
class Session:
    """A stored session. ``token`` is a secret -- it is never logged/printed."""

    api_url: str
    token: str
    expires_at: str | None = None
    subject: str | None = None


class TokenStore:
    """JSON-file-backed store for the current CLI session.

    The path is resolved once at construction (or injected, so tests point it at
    a temp file). All writes go through ``save`` (0600); ``load`` fail-closes on
    an over-permissive file.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path is not None else config_path()

    @property
    def path(self) -> Path:
        return self._path

    def save(self, session: Session) -> None:
        """Persist ``session`` atomically-ish with strict permissions.

        The parent directory is created ``0700``; the file is opened ``0600`` and
        its mode is re-enforced afterwards so a pre-existing, looser file is
        tightened rather than trusted. The token is written ONLY here."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._path.parent, _DIR_MODE)
        except OSError:  # pragma: no cover - non-owned dir (e.g. injected /tmp)
            pass
        payload = {
            "api_url": session.api_url,
            "token": session.token,
            "expires_at": session.expires_at,
            "subject": session.subject,
        }
        data = json.dumps(payload, indent=2, sort_keys=True)
        # Open with O_CREAT|O_TRUNC at 0600 so the token is never briefly written
        # through a wider mode; then chmod to enforce 0600 even if the file
        # pre-existed with looser bits (open() does not shrink an existing file's
        # mode).
        fd = os.open(
            self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(data)
        finally:
            os.chmod(self._path, _FILE_MODE)

    def load(self) -> Session | None:
        """Return the stored session, or ``None`` when absent.

        REFUSES (warns + returns ``None``) a file that is readable by group or
        others -- a permission leak must not become a silently trusted
        credential. A malformed/partial file is likewise ignored (``None``)."""
        try:
            info = self._path.stat()
        except FileNotFoundError:
            return None
        except OSError as exc:  # pragma: no cover - unreadable path
            _logger.warning("cannot stat credentials file: %s", exc)
            return None
        if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            _logger.warning(
                "ignoring credentials file %s: it is group/world accessible "
                "(run: chmod 600 %s)",
                self._path,
                self._path,
            )
            print(
                f"warning: ignoring credentials at {self._path}: too permissive "
                f"(chmod 600 {self._path})",
                file=sys.stderr,
            )
            return None
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            _logger.warning("ignoring unreadable credentials file: %s", exc)
            return None
        if not isinstance(payload, dict) or not payload.get("token"):
            return None
        return Session(
            api_url=str(payload.get("api_url", "")),
            token=str(payload["token"]),
            expires_at=payload.get("expires_at"),
            subject=payload.get("subject"),
        )

    def clear(self) -> None:
        """Remove the credentials file (idempotent)."""
        try:
            self._path.unlink()
        except FileNotFoundError:
            pass
