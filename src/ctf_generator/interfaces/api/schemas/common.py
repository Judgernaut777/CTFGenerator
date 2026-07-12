"""Shared response models: the ``ctfgen.error`` envelope + the standard error
response set referenced by every route so the generated OpenAPI documents the
envelope for each status code."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ctf_generator.schema import ERROR_SCHEMA


class ErrorDetail(BaseModel):
    field: str = Field(description="JSON path of the offending field")
    issue: str = Field(description="What is wrong with it")


class ErrorBody(BaseModel):
    code: str = Field(description="Stable machine-readable error token")
    message: str = Field(description="Human-readable; not for programmatic branching")
    request_id: str = Field(description="Correlation id, echoed from X-Request-ID")
    details: list[ErrorDetail] | None = Field(
        default=None, description="Optional per-field validation problems"
    )


class ErrorEnvelope(BaseModel):
    """The single envelope every non-2xx response uses (``ctfgen.error``)."""

    model_config = ConfigDict(populate_by_name=True)

    schema_id: str = Field(
        default=ERROR_SCHEMA, alias="schema", serialization_alias="schema"
    )
    schema_version: str = Field(default="1.0")
    error: ErrorBody


class PageInfo(BaseModel):
    limit: int
    next_cursor: str | None = None
    has_more: bool = False


def _err(description: str) -> dict[str, Any]:
    return {"model": ErrorEnvelope, "description": description}


# The standard error responses attached to routes (documentation only; the
# runtime bodies are produced by the exception handlers). Individual routes merge
# in the subset they can actually return.
ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    400: _err("Malformed request or unknown parameter"),
    401: _err("Missing or invalid credentials"),
    403: _err("Authenticated but not permitted"),
    404: _err("Resource not found"),
    409: _err("State conflict / duplicate / idempotency-key reuse"),
    412: _err("Stale If-Match precondition"),
    422: _err("Well-formed but semantically invalid"),
    428: _err("Required If-Match precondition missing"),
    429: _err("Rate limited"),
    500: _err("Internal error"),
}
