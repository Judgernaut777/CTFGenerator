"""The ``ctfgen`` console entry point: a dispatcher that PRESERVES the legacy
generator CLI while adding the supported platform areas (M13 slice 13a).

Dispatch rule: if the first argument names a known platform AREA (this slice:
``auth``), route to the platform dispatcher (which talks HTTP and needs the
``[cli]`` extra); otherwise delegate UNCHANGED to the legacy generator CLI
(:func:`ctf_generator.cli.main`), so every existing ``ctfgen`` command behaves
exactly as before.

Why this shape:

* The legacy path NEVER imports httpx or the API -- the platform module is
  imported LAZILY, only inside the area branch, so an install without the
  ``[cli]`` extra still runs every generator command. A missing httpx on an
  ``auth`` command becomes a clean "install the extra" message, not a traceback.
* Routing is by the first token only, so global flags belong AFTER the verb
  (``ctfgen auth login --api-url ...``); a bare ``ctfgen`` or any legacy command
  is untouched.
"""

from __future__ import annotations

import sys

# The platform areas whose first token routes to the HTTP CLI. Kept in sync with
# ``platform.PLATFORM_AREAS`` but declared here WITHOUT importing platform (which
# pulls in httpx) so the legacy path never triggers that import.
_PLATFORM_AREAS = frozenset({"auth"})


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in _PLATFORM_AREAS:
        return _run_platform(args)
    # Legacy generator CLI -- imported here so nothing about the platform side
    # (httpx, the API) is required to run a generator command.
    from ctf_generator.cli import main as legacy_main

    return legacy_main(args)


def _run_platform(args: list[str]) -> int:
    try:
        from .platform import main as platform_main
    except ImportError:
        # httpx (the [cli] extra) is not installed. Fail cleanly -- never a
        # traceback -- and tell the user exactly how to enable the area.
        print(
            f"the '{args[0]}' commands require the CLI extra: "
            "pip install 'ctf-generator[cli]'",
            file=sys.stderr,
        )
        return 1
    return platform_main(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
