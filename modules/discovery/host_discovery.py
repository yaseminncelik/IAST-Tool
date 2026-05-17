from __future__ import annotations

from pathlib import Path

from config.settings import (
    SCAN_INPUT_DIR,
    OUTPUTS_DIR,
    ALIVE_HOSTS_FILE,
    DISCOVERY_GNMAP,
    DISCOVERY_PORTS_TCP,
    DISCOVERY_PORTS_ACK,
    SUBPROCESS_TIMEOUT,
)
from core.logger import get_logger
from core.platform_utils import run_nmap

logger = get_logger("discovery")


def run_discovery(ip_range: str) -> None:
    SCAN_INPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    logger.info(f"Nmap discovery başlıyor... Hedef: {ip_range}")

    nmap_args = [
        "-sn",
        "-PE", "-PP", "-PM",
        f"-PS{DISCOVERY_PORTS_TCP}",
        f"-PA{DISCOVERY_PORTS_ACK}",
        ip_range,
        "-oG", str(DISCOVERY_GNMAP),
        "-n",
    ]

    try:
        run_nmap(nmap_args, timeout=SUBPROCESS_TIMEOUT)
    except FileNotFoundError as e:
        logger.error(str(e))
        return
    except Exception as e:
        logger.error(f"Nmap çalıştırılamadı: {e}")
        return

    _extract_alive_hosts(DISCOVERY_GNMAP)


def _extract_alive_hosts(gnmap_file: Path) -> None:
    logger.info("Alive hostlar çıkarılıyor...")

    if not gnmap_file.is_file():
        logger.error(f"gnmap dosyası bulunamadı: {gnmap_file}")
        return

    alive_hosts = []
    try:
        with open(gnmap_file, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#"):
                    continue
                if "Status: Up" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        alive_hosts.append(parts[1])
    except OSError as e:
        logger.error(f"Dosya okunamadı: {e}")
        return

    if not alive_hosts:
        logger.warning("Hiçbir alive host bulunamadı.")
        return

    ALIVE_HOSTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(ALIVE_HOSTS_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(alive_hosts) + "\n")
    except OSError as e:
        logger.error(f"Alive hosts dosyası yazılamadı: {e}")
        return

    logger.info(f"[+] {len(alive_hosts)} alive host kaydedildi → {ALIVE_HOSTS_FILE}")