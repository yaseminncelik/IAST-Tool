from __future__ import annotations

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


def get_platform_info() -> dict:
    return {
        "os":      platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python":  sys.version.split()[0],
    }


def check_admin() -> bool:
    try:
        if IS_WINDOWS:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return os.getuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def find_tool(tool_name: str) -> Optional[str]:
    if IS_WINDOWS and not tool_name.endswith(".exe"):
        return shutil.which(tool_name + ".exe") or shutil.which(tool_name)
    return shutil.which(tool_name)


def get_nmap_path() -> Optional[str]:
    path = find_tool("nmap")
    if path:
        return path
    if IS_WINDOWS:
        for candidate in [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ]:
            if Path(candidate).is_file():
                return candidate
    return None


def get_rustscan_path() -> Optional[str]:
    return find_tool("rustscan")


def safe_run(
    cmd: List[str],
    timeout: int = 300,
    capture_output: bool = False,
    cwd: Optional[Path] = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        shell=False,
        timeout=timeout,
        capture_output=capture_output,
        text=True,
        cwd=cwd,
    )


def run_nmap(args: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
    nmap_path = get_nmap_path()
    if not nmap_path:
        raise FileNotFoundError(
            "Nmap bulunamadı.\n"
            "  Windows: https://nmap.org/download.html\n"
            "  Linux:   sudo apt install nmap"
        )
    return safe_run([nmap_path] + args, timeout=timeout)
