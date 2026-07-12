"""The ``ctfgen <area> <verb>`` platform command groups (M13 slice 13b).

One module per area, each exposing ``AREA`` (the first-token area name) and
``add_parser(areas_subparsers)`` (registers its verbs onto the platform
dispatcher). :data:`AREA_MODULES` is the single ordered registry the dispatcher
iterates; :data:`AREA_NAMES` is the derived set of area names that
``platform.PLATFORM_AREAS`` / ``entry._PLATFORM_AREAS`` must stay in sync with.
"""

from __future__ import annotations

import argparse

from . import (
    builds,
    challenge_defs,
    challenge_versions,
    competitions,
    instances,
    jobs,
    publications,
    submissions,
    system,
    teams,
    users,
)

# Ordered so ``--help`` lists areas predictably. Every module has AREA + add_parser.
AREA_MODULES = (
    competitions,
    teams,
    users,
    challenge_defs,
    challenge_versions,
    publications,
    submissions,
    instances,
    jobs,
    builds,
    system,
)

AREA_NAMES = frozenset(module.AREA for module in AREA_MODULES)


def register_all(areas: argparse._SubParsersAction) -> None:
    """Register every area's verbs onto the platform dispatcher's subparsers."""
    for module in AREA_MODULES:
        module.add_parser(areas)
