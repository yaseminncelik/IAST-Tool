"""
Platform tespiti ve güvenli subprocess yardımcıları.
OS'a göre doğru komutları ve yolları döndürür.
"""

import os
import sys
import platform
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional


IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MACOS   = platform.system() == "Darwin"

PLATFORM_NAME = platform.system()


def get_platform_info() -> dict:
    """Sistem bilgilerini döndürür."""
    return {
        "os":       platform.system(),
        "release":  platform.release(),
        "version":  platform.version(),
        "machine":  platform.machine(),
        "python":   sys.version.split()[0],
    }


def check_admin() -> bool:
    """
    Programın yönetici/root yetkisiyle çalışıp çalışmadığını kontrol eder.
    Nmap raw socket taramaları için gereklidir.
    """
    try:
        if IS_WINDOWS:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return os.getuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def find_tool(tool_name: str) -> Optional[str]:
    """
    Belirtilen aracın PATH'teki konumunu döndürür.
    Bulunamazsa None döndürür.
    """
    if IS_WINDOWS and not tool_name.endswith(".exe"):
        path = shutil.which(tool_name + ".exe") or shutil.which(tool_name)
    else:
        path = shutil.which(tool_name)
    return path


def get_nmap_path() -> Optional[str]:
    """
    Nmap'in sistem yolunu döndürür.
    Windows'ta varsayılan kurulum konumlarını da kontrol eder.
    """
    path = find_tool("nmap")
    if path:
        return path

    if IS_WINDOWS:
        candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ]
        for candidate in candidates:
            if Path(candidate).is_file():
                return candidate

    return None


def get_rustscan_path() -> Optional[str]:
    """RustScan yolunu döndürür (yalnızca Linux/macOS'ta anlamlı)."""
    return find_tool("rustscan")


def safe_run(
    cmd: List[str],
    timeout: int = 600,
    capture_output: bool = False,
    cwd: Optional[Path] = None,
) -> subprocess.CompletedProcess:
    """
    Güvenli subprocess.run() sarmalayıcı.
    - shell=False (komut enjeksiyonu riski yok)
    - Liste formatında komut argümanları
    - Yapılandırılabilir timeout
    """
    return subprocess.run(
        cmd,
        shell=False,
        timeout=timeout,
        capture_output=capture_output,
        text=True,
        cwd=cwd,
    )


def run_nmap(args: List[str], timeout: int = 600) -> subprocess.CompletedProcess:
    """
    Nmap'i doğru yoldan çalıştırır.
    nmap_path bulunamazsa hata fırlatır.
    """
    nmap_path = get_nmap_path()
    if not nmap_path:
        raise FileNotFoundError(
            "Nmap bulunamadı. Lütfen yükleyin:\n"
            "  Windows: https://nmap.org/download.html\n"
            "  Linux:   sudo apt install nmap"
        )
    return safe_run([nmap_path] + args, timeout=timeout)
