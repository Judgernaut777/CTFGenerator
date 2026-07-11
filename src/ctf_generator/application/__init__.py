"""Application layer: use-case services that orchestrate the domain.

Depends only on ``domain`` types/protocols and on infrastructure *protocols*
(never concrete infrastructure). Interfaces (CLI/API/web/MCP) call these
services so every entry point shares one code path; no business logic lives in
route handlers or argument parsers.
"""
