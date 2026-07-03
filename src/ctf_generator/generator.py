from __future__ import annotations

import hashlib
import json
import random
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from . import families
from .models import ChallengeSpec
from .spec_generator import default_spec
from .yaml_writer import dump_yaml

if TYPE_CHECKING:
    from .cve_source import CveRecord, CveSource


def create_challenge(
    output_dir: Path,
    seed: str,
    title: str,
    difficulty: str,
    family: str,
    force: bool = False,
    spec: ChallengeSpec | None = None,
    cve_record: "CveRecord | None" = None,
) -> Path:
    if output_dir.exists():
        if not force:
            raise FileExistsError(f"{output_dir} already exists; pass --force to overwrite")
        shutil.rmtree(output_dir)

    # Spec-first: when a caller supplies a structured spec (e.g. from `ctfgen
    # spec`), it is the source of truth, including its seed. Otherwise fall back
    # to the built-in deterministic spec for this family.
    if spec is None:
        spec = default_spec(seed=seed, title=title, difficulty=difficulty, family=family)

    rng = random.Random(_seed_int(spec.seed))
    files = families.get(spec.family).render(spec, rng, cve_record)
    files["challenge.yaml"] = dump_yaml(spec.to_mapping())

    for relative_path, content in files.items():
        path = output_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    if spec.scenario.enabled:
        timeline_path = output_dir / "private/scenario_timeline.json"
        timeline_path.parent.mkdir(parents=True, exist_ok=True)
        timeline_path.write_text(
            json.dumps(spec.scenario.to_mapping(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return output_dir


def create_challenge_from_cve(
    output_dir: Path,
    cve_id: str,
    base_seed: str,
    difficulty: str | None = None,
    family: str | None = None,
    title: str | None = None,
    force: bool = False,
    source: "CveSource | None" = None,
) -> Path:
    """Generate a challenge grounded in a real CVE record.

    Resolves ``cve_id`` via ``source`` (defaulting to the offline, deterministic
    ``SnapshotCveSource``), builds a themed ``ChallengeSpec`` from it via
    ``cve_blueprint.spec_from_cve``, and renders it exactly like
    ``create_challenge`` -- including passing the resolved ``CveRecord``
    through to the family renderer.
    """
    from . import cve_blueprint
    from .cve_source import get_source

    resolved_source = source if source is not None else get_source("snapshot")
    record = resolved_source.get(cve_id)
    if record is None:
        raise ValueError(f"unknown CVE id: {cve_id}")

    spec = cve_blueprint.spec_from_cve(
        record,
        base_seed=base_seed,
        family=family,
        difficulty=difficulty,
        title=title,
    )

    return create_challenge(
        output_dir=output_dir,
        seed=spec.seed,
        title=spec.title,
        difficulty=spec.difficulty,
        family=spec.family,
        force=force,
        spec=spec,
        cve_record=record,
    )


def _seed_int(seed: str) -> int:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return int(digest[:16], 16)


# Public alias: some callers (e.g. CVE-driven / scenario code) want the seed
# -> int conversion without reaching into a private name.
seed_to_int = _seed_int
