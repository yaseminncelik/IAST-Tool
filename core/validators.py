"""
Input validasyon yardımcıları.
IP adresi, CIDR aralığı ve dosya yolu doğrulaması.
"""

import ipaddress
import re
from pathlib import Path
from typing import Union


def validate_ip_range(value: str) -> bool:
    """
    Tekil IP (192.168.1.1), CIDR (192.168.1.0/24)
    veya aralık (192.168.1.1-254) formatlarını doğrular.
    """
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

    range_pattern = re.compile(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$"
    )
    if range_pattern.match(value):
        return True

    return False


def validate_file_path(path: Union[str, Path], base_dir: Path) -> bool:
    """
    Dosya yolunun base_dir içinde kaldığını doğrular (path traversal önleme).
    """
    try:
        resolved = Path(path).resolve()
        base_resolved = base_dir.resolve()
        return resolved.is_relative_to(base_resolved)
    except (ValueError, OSError):
        return False


def sanitize_filename(name: str) -> str:
    """
    Dosya adından tehlikeli karakterleri temizler.
    """
    safe = re.sub(r"[^\w.\-]", "_", name.strip())
    if not safe or safe in (".", ".."):
        raise ValueError(f"Geçersiz dosya adı: '{name}'")
    return safe
