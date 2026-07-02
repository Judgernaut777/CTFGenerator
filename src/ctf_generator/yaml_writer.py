from __future__ import annotations


def dump_yaml(value: object, indent: int = 0) -> str:
    lines: list[str] = []
    _write_yaml(lines, value, indent)
    return "\n".join(lines) + "\n"


def _write_yaml(lines: list[str], value: object, indent: int) -> None:
    prefix = " " * indent
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                lines.append(f"{prefix}{key}:")
                _write_yaml(lines, child, indent + 2)
            else:
                lines.append(f"{prefix}{key}: {_scalar(child)}")
        return

    if isinstance(value, list):
        if not value:
            lines.append(f"{prefix}[]")
            return
        for item in value:
            if isinstance(item, dict):
                lines.append(f"{prefix}-")
                _write_yaml(lines, item, indent + 2)
            elif isinstance(item, list):
                lines.append(f"{prefix}-")
                _write_yaml(lines, item, indent + 2)
            else:
                lines.append(f"{prefix}- {_scalar(item)}")
        return

    lines.append(f"{prefix}{_scalar(value)}")


def _scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'

