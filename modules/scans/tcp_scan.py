"""
TCP Tarama modülü.
- Linux + RustScan mevcut: RustScan ile hızlı port keşfi → Nmap ile servis/versiyon tespiti
- Linux + RustScan yok  : Yalnızca Nmap
- Windows               : Yalnızca Nmap (RustScan Windows'ta desteklenmez)
- ThreadPoolExecutor ile paralel host taraması
- shell=False, liste formatında komutlar
- pathlib ile platform bağımsız yollar
"""

from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List

from config.settings import (
    SCAN_INPUT_DIR,
    SCAN_OUTPUT_DIR,
    ALIVE_HOSTS_FILE,
    SUBPROCESS_TIMEOUT,
)
from core.logger import get_logger
from core.platform_utils import (
    IS_WINDOWS,
    get_rustscan_path,
    get_nmap_path,
    run_nmap,
)

logger = get_logger("scans.tcp")

_MAX_WORKERS = 3  # Paralel tarama sayısı


def tcp_scan(input_file: str = "") -> None:
    """
    Verilen host listesi dosyasını okuyarak TCP tarama başlatır.
    Her host için ayrı bir thread kullanılır.
    """
    target_file = _resolve_input(input_file)
    if target_file is None:
        return

    hosts = _read_hosts(target_file)
    if not hosts:
        logger.error("Host listesi boş veya dosya okunamadı.")
        return

    SCAN_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    base_name = target_file.stem

    use_rustscan = not IS_WINDOWS and get_rustscan_path() is not None
    engine = "RustScan + Nmap" if use_rustscan else "Nmap"
    logger.info(f"TCP tarama başlıyor ({engine}) — {len(hosts)} host, {_MAX_WORKERS} thread")

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
        futures = {
            executor.submit(_scan_host, host, base_name, use_rustscan): host
            for host in hosts
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                future.result()
            except Exception as e:
                logger.error(f"[{host}] Tarama hatası: {e}")

    _merge_nmap_outputs(base_name)

    full_output = SCAN_OUTPUT_DIR / f"tcp_{base_name}_full.txt"
    logger.info(f"[+] TCP tarama tamamlandı → {SCAN_OUTPUT_DIR}")
    logger.info(f"[+] Birleşik çıktı → {full_output}")


# ─── Yardımcı Fonksiyonlar ────────────────────────────────────────────────────

def _resolve_input(input_file: str) -> Path | None:
    """Dosya yolunu çözer; bulunamazsa None döndürür."""
    if not input_file:
        path = ALIVE_HOSTS_FILE
    else:
        path = Path(input_file)
        if not path.is_absolute():
            path = SCAN_INPUT_DIR / path

    if not path.is_file():
        logger.error(f"Input dosyası bulunamadı: {path}")
        return None
    return path


def _read_hosts(file_path: Path) -> List[str]:
    """Dosyadan host listesini okur."""
    try:
        with open(file_path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except OSError as e:
        logger.error(f"Dosya okunamadı: {e}")
        return []


def _scan_host(host: str, base_name: str, use_rustscan: bool) -> None:
    """Tek bir host'u tarar."""
    out_prefix = str(SCAN_OUTPUT_DIR / f"tcp_{base_name}_{host}")

    if use_rustscan:
        _rustscan_then_nmap(host, out_prefix)
    else:
        _nmap_only(host, out_prefix)


def _nmap_only(host: str, out_prefix: str) -> None:
    """Yalnızca Nmap ile tam port + servis taraması."""
    nmap_args = [
        "-Pn", "-sVC", "-O",
        "--min-rate", "1000",
        "-T4",
        "-p", "0-65535",
        host,
        "-oA", out_prefix,
    ]
    try:
        logger.info(f"  [*] Nmap taranıyor: {host}")
        run_nmap(nmap_args, timeout=SUBPROCESS_TIMEOUT)
    except FileNotFoundError as e:
        logger.error(str(e))
    except subprocess.TimeoutExpired:
        logger.warning(f"  [!] Timeout: {host}")
    except Exception as e:
        logger.error(f"  [!] Nmap hatası ({host}): {e}")


def _rustscan_then_nmap(host: str, out_prefix: str) -> None:
    """RustScan ile hızlı port keşfi, ardından Nmap ile detaylı tarama."""
    rustscan_path = get_rustscan_path()
    nmap_path = get_nmap_path()

    if not rustscan_path or not nmap_path:
        logger.warning(f"  [!] RustScan veya Nmap bulunamadı, atlıyorum: {host}")
        return

    rustscan_cmd = [
        rustscan_path,
        "-a", host,
        "-b", "1000",
        "--ulimit", "100000",
        "-r", "0-65535",
        "--",
        "-Pn", "-sVC", "-O",
        "-oA", out_prefix,
    ]

    try:
        logger.info(f"  [*] RustScan taranıyor: {host}")
        subprocess.run(
            rustscan_cmd,
            shell=False,
            timeout=SUBPROCESS_TIMEOUT,
            text=True,
        )
    except subprocess.TimeoutExpired:
        logger.warning(f"  [!] RustScan timeout: {host}")
    except Exception as e:
        logger.error(f"  [!] RustScan hatası ({host}): {e}")


def _merge_nmap_outputs(base_name: str) -> None:
    """
    Bireysel .nmap dosyalarını tek bir full.txt'e birleştirir.
    cat komutu yerine Pure Python ile yapılır (Windows uyumlu).
    """
    nmap_files = sorted(SCAN_OUTPUT_DIR.glob(f"tcp_{base_name}_*.nmap"))
    if not nmap_files:
        logger.warning("Birleştirilecek .nmap dosyası bulunamadı.")
        return

    full_output = SCAN_OUTPUT_DIR / f"tcp_{base_name}_full.txt"
    try:
        with open(full_output, "w", encoding="utf-8") as out:
            for nmap_file in nmap_files:
                try:
                    content = nmap_file.read_text(encoding="utf-8", errors="ignore")
                    out.write(content)
                    out.write("\n")
                except OSError as e:
                    logger.warning(f"Dosya okunamadı ({nmap_file.name}): {e}")
    except OSError as e:
        logger.error(f"Birleşik dosya oluşturulamadı: {e}")