"""
UDP Tarama modülü.
Nmap -sU ile en yaygın UDP portlarını tarar.
NOT: Raw socket gerektirir → Linux'ta root, Windows'ta Admin yetkisi zorunludur.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List

from config.settings import (
    SCAN_OUTPUT_DIR,
    UDP_COMMON_PORTS,
    SUBPROCESS_TIMEOUT,
)
from core.logger import get_logger
from core.platform_utils import check_admin, run_nmap

logger = get_logger("scans.udp")


def udp_scan(hosts: List[str]) -> None:
    """
    Verilen host listesi için UDP taraması yapar.
    Her host ayrı ayrı taranır.
    """
    if not hosts:
        logger.warning("Host listesi boş, UDP tarama atlandı.")
        return

    if not check_admin():
        logger.warning(
            "UDP taraması (Nmap -sU) yönetici/root yetkisi gerektirir.\n"
            "  Windows: Yönetici olarak çalıştırın\n"
            "  Linux:   sudo python main.py"
        )

    SCAN_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    logger.info(f"UDP tarama başlıyor — {len(hosts)} host, portlar: {UDP_COMMON_PORTS}")

    for host in hosts:
        _scan_host_udp(host)

    logger.info(f"[+] UDP tarama tamamlandı → {SCAN_OUTPUT_DIR}")


def _scan_host_udp(host: str) -> None:
    """Tek bir host için UDP taraması yapar."""
    out_prefix = str(SCAN_OUTPUT_DIR / f"udp_{host}")

    nmap_args = [
        "-sU",
        "-Pn",
        "-p", UDP_COMMON_PORTS,
        "--version-intensity", "0",   # Hız için düşük yoğunluk
        "-T4",
        host,
        "-oA", out_prefix,
    ]

    try:
        logger.info(f"  [*] UDP taranıyor: {host}")
        run_nmap(nmap_args, timeout=SUBPROCESS_TIMEOUT)
    except FileNotFoundError as e:
        logger.error(str(e))
    except subprocess.TimeoutExpired:
        logger.warning(f"  [!] Timeout: {host}")
    except Exception as e:
        logger.error(f"  [!] UDP tarama hatası ({host}): {e}")