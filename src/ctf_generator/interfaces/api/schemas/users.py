"""User DTOs + mappers (maps the domain ``User``, keyed by ``email``).

The registration request carries a ``role`` (validated against the identity
domain's :data:`VALID_ROLES`) for forward-compatibility, but role/team placement
is competition-scoped (a ``Membership``) and is assigned through the membership
surface, not stored on the global user profile -- so ``role`` is validated at the
boundary and used only for the audit trail, never echoed as if persisted (see
docs/api/slice-a-limitations.md). No credential/secret is modelled: the profile
is only ``email`` + ``display_name``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from ctf_generator.domain.identity.models import VALID_ROLES, User


class UserCreateRequest(BaseModel):
    email: str = Field(min_length=1, description="Case-insensitive business identity")
    display_name: str = Field(min_length=1)
    role: str = Field(
        min_length=1,
        description="Requested competition role (validated against VALID_ROLES)",
    )

    @field_validator("role")
    @classmethod
    def _role_is_valid(cls, value: str) -> str:
        if value not in VALID_ROLES:
            raise ValueError(
                f"role must be one of {sorted(VALID_ROLES)}, got {value!r}"
            )
        return value

    def to_domain(self) -> User:
        return User(email=self.email, display_name=self.display_name)


class UserResponse(BaseModel):
    email: str
    display_name: str


def user_concurrency_payload(user: User) -> dict[str, Any]:
    return {"email": user.email, "display_name": user.display_name}


def user_to_response(user: User) -> dict[str, Any]:
    return {"email": user.email, "display_name": user.display_name}
