from __future__ import annotations

import hashlib
import random
import shutil
from pathlib import Path

from .models import ChallengeSpec
from .templates.tenant_export import render_tenant_export
from .yaml_writer import dump_yaml


def create_challenge(
    output_dir: Path,
    seed: str,
    title: str,
    difficulty: str,
    family: str,
    force: bool = False,
) -> Path:
    if output_dir.exists():
        if not force:
            raise FileExistsError(f"{output_dir} already exists; pass --force to overwrite")
        shutil.rmtree(output_dir)

    rng = random.Random(_seed_int(seed))
    spec = ChallengeSpec(
        title=title,
        category="web",
        difficulty=difficulty,
        family=family,
        seed=seed,
        learning_objectives=[
            "Trace an authorization boundary across API and worker services",
            "Identify a legacy trust mismatch in a stateful export workflow",
            "Write a robust exploit that adapts to generated route and data variants",
        ],
        checkpoints=[
            "discovers profile and notice endpoints",
            "identifies the export workflow",
            "finds cross-tenant invoice metadata",
            "queues a legacy export job with attacker-controlled tenant reference",
            "retrieves the generated export and extracts the flag",
        ],
    )

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

