from __future__ import annotations

import hashlib
import random
import shutil
from pathlib import Path

from .models import ChallengeSpec
from .spec_generator import default_spec
from .templates.tenant_export import render_tenant_export
from .yaml_writer import dump_yaml


def create_challenge(
    output_dir: Path,
    seed: str,
    title: str,
    difficulty: str,
    family: str,
    force: bool = False,
    spec: ChallengeSpec | None = None,
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
    files = render_tenant_export(spec=spec, rng=rng)
    files["challenge.yaml"] = dump_yaml(spec.to_mapping())

    for relative_path, content in files.items():
        path = output_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    return output_dir


def _seed_int(seed: str) -> int:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return int(digest[:16], 16)

