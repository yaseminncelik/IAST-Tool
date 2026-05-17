from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Union


def validate_ip_range(value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$", value):
        return True
    return False


def validate_file_path(path: Union[str, Path], base_dir: Path) -> bool:
    try:
        return Path(path).resolve().is_relative_to(base_dir.resolve())
    except (ValueError, OSError):
        return False


def sanitize_filename(name: str) -> str:
    safe = re.sub(r"[^\w.\-]", "_", name.strip())
    if not safe or safe in (".", ".."):
        raise ValueError(f"Geçersiz dosya adı: '{name}'")
    return safe
