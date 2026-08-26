"""Private, immutable answer-verifier specs used by the submission service."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol


class AnswerSpecError(ValueError):
    """An author supplied malformed private answer-verifier data."""


class AnswerSpec(Protocol):
    def matches(self, candidate: str) -> bool: ...

    def to_mapping(self) -> dict[str, object]: ...


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise AnswerSpecError(f"{name} must be a mapping")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AnswerSpecError(f"{name} must be a non-empty string")
    return value


def _normalized_text(value: str) -> str:
    return "".join(ch for ch in value.casefold() if ch.isalnum())


@dataclass(frozen=True)
class AliasesAnswerSpec:
    answers: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.answers or any(
            not isinstance(item, str) or not item.strip() for item in self.answers
        ):
            raise AnswerSpecError("aliases.answers must contain non-empty strings")

    def matches(self, candidate: str) -> bool:
        normalized = _normalized_text(candidate)
        return any(_normalized_text(answer) == normalized for answer in self.answers)

    def to_mapping(self) -> dict[str, object]:
        return {"kind": "aliases", "answers": list(self.answers)}


@dataclass(frozen=True)
class CoordinateAnswerSpec:
    latitude: float
    longitude: float
    tolerance_meters: float

    def __post_init__(self) -> None:
        if not -90 <= self.latitude <= 90:
            raise AnswerSpecError("coordinate.latitude must be between -90 and 90")
        if not -180 <= self.longitude <= 180:
            raise AnswerSpecError("coordinate.longitude must be between -180 and 180")
        if not math.isfinite(self.tolerance_meters) or self.tolerance_meters < 0:
            raise AnswerSpecError("coordinate.tolerance_meters must be finite and >= 0")

    def matches(self, candidate: str) -> bool:
        try:
            latitude_text, longitude_text = candidate.split(",", maxsplit=1)
            latitude, longitude = float(latitude_text.strip()), float(longitude_text.strip())
        except (TypeError, ValueError):
            return False
        if not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
            return False
        radius_meters = 6_371_000.0
        lat1, lon1, lat2, lon2 = map(
            math.radians, (self.latitude, self.longitude, latitude, longitude)
        )
        delta_lat, delta_lon = lat2 - lat1, lon2 - lon1
        a = (
            math.sin(delta_lat / 2) ** 2
            + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
        )
        return radius_meters * 2 * math.asin(math.sqrt(a)) <= self.tolerance_meters

    def to_mapping(self) -> dict[str, object]:
        return {
            "kind": "coordinate",
            "latitude": self.latitude,
            "longitude": self.longitude,
            "tolerance_meters": self.tolerance_meters,
        }


@dataclass(frozen=True)
class IdentifierAnswerSpec:
    value: str
    strip_prefixes: tuple[str, ...] = ()
    strip_separators: bool = False

    def __post_init__(self) -> None:
        _string(self.value, "identifier.value")
        if any(not isinstance(prefix, str) or not prefix for prefix in self.strip_prefixes):
            raise AnswerSpecError("identifier.strip_prefixes must contain non-empty strings")

    def _normalize(self, value: str) -> str:
        normalized = value.casefold().strip()
        for prefix in self.strip_prefixes:
            lowered = prefix.casefold()
            if normalized.startswith(lowered):
                normalized = normalized[len(lowered) :]
                break
        return re.sub(r"[^a-z0-9]", "", normalized) if self.strip_separators else normalized

    def matches(self, candidate: str) -> bool:
        return self._normalize(candidate) == self._normalize(self.value)

    def to_mapping(self) -> dict[str, object]:
        return {
            "kind": "identifier",
            "value": self.value,
            "strip_prefixes": list(self.strip_prefixes),
            "strip_separators": self.strip_separators,
        }


@dataclass(frozen=True)
class MultipartAnswerSpec:
    fields: tuple[tuple[str, AnswerSpec], ...]

    def __post_init__(self) -> None:
        if not self.fields or any(not key.strip() for key, _value in self.fields):
            raise AnswerSpecError("multipart.fields must contain named answer specifications")
        if len({key for key, _value in self.fields}) != len(self.fields):
            raise AnswerSpecError("multipart.fields names must be unique")

    def matches(self, candidate: str) -> bool:
        try:
            supplied = json.loads(candidate)
        except (TypeError, ValueError):
            return False
        if not isinstance(supplied, dict):
            return False
        return all(
            isinstance(supplied.get(name), str) and spec.matches(supplied[name])
            for name, spec in self.fields
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "kind": "multipart",
            "fields": {name: spec.to_mapping() for name, spec in self.fields},
        }


def parse_answer_spec(value: object) -> AnswerSpec:
    """Validate untrusted author data into a frozen answer-verifier value."""
    data = _mapping(value, "answer_verifier")
    kind = _string(data.get("kind"), "answer_verifier.kind")
    if kind == "aliases":
        raw_answers = data.get("answers")
        if not isinstance(raw_answers, (list, tuple)):
            raise AnswerSpecError("aliases.answers must be a list")
        return AliasesAnswerSpec(
            tuple(_string(item, "aliases.answers item") for item in raw_answers)
        )
    if kind == "coordinate":
        try:
            return CoordinateAnswerSpec(
                float(data["latitude"]), float(data["longitude"]), float(data["tolerance_meters"])
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AnswerSpecError(
                "coordinate requires numeric latitude, longitude, and tolerance_meters"
            ) from exc
    if kind == "identifier":
        prefixes = data.get("strip_prefixes", [])
        if not isinstance(prefixes, (list, tuple)) or not isinstance(
            data.get("strip_separators", False), bool
        ):
            raise AnswerSpecError("identifier normalization options are malformed")
        return IdentifierAnswerSpec(
            _string(data.get("value"), "identifier.value"),
            tuple(_string(prefix, "identifier prefix") for prefix in prefixes),
            data.get("strip_separators", False),
        )
    if kind == "multipart":
        fields = _mapping(data.get("fields"), "multipart.fields")
        return MultipartAnswerSpec(
            tuple((str(name), parse_answer_spec(item)) for name, item in fields.items())
        )
    raise AnswerSpecError(f"unsupported answer_verifier.kind: {kind!r}")
