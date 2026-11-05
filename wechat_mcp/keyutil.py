"""Shared helpers for parsing and validating manually supplied keys."""

from __future__ import annotations

import re

from .errors import KeyInvalid

KEY_SPLIT_RE = re.compile(r"[;,\s]+")


def parse_key_hex(value: str) -> tuple[bytes, bytes | None]:
    text = value.strip().lower()
    if text.startswith("x'") and text.endswith("'"):
        text = text[2:-1]
    try:
        if len(text) == 96:
            return bytes.fromhex(text[:64]), bytes.fromhex(text[64:96])
        return bytes.fromhex(text), None
    except ValueError as exc:
        raise KeyInvalid("key 必须是 64 位（或带 salt 的 96 位）十六进制字符串") from exc


def parse_key_list(value: str) -> list[tuple[bytes, bytes | None]]:
    """Parse one or more keys separated by newlines, semicolons, or commas.

    4.1+ uses a different key per database, so users may need to provide
    several keys.  A 96-hex value is treated as ``key + salt``.
    """
    items: list[tuple[bytes, bytes | None]] = []
    for part in KEY_SPLIT_RE.split(value.strip()):
        if part:
            items.append(parse_key_hex(part))
    if not items:
        raise KeyInvalid("key 不能为空")
    return items


def plausible_key(key: bytes | None, minimum_distinct: int = 8) -> bool:
    if not key or len(key) != 32:
        return False
    return len(set(key)) >= minimum_distinct
