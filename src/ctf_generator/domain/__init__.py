"""Domain layer: pure business types and rules for CTFGenerator.

Dependency rule (enforced by tests/test_architecture_boundaries.py): modules
under ``domain`` MUST NOT import any framework, I/O, or infrastructure code --
no http/asgi, docker/subprocess, postgres/sqlalchemy, MCP, or LLM SDKs. Only
the Python standard library and other ``domain`` modules. This keeps the core
model testable in isolation and reusable by every interface (CLI, API, MCP).
"""
