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
    TCP_FAST_PORTS,
    TCP_SCAN_PORTS,
)
from core.logger import get_logger
from core.platform_utils import IS_WINDOWS, get_rustscan_path, get_nmap_path, run_nmap

logger = get_logger("scans.tcp")

_MAX_WORKERS = 3


def tcp_scan(input_file: str = "", full_scan: bool = False) -> None:
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
    mode = "TAM (0-65535)" if full_scan else "HIZLI"
    logger.info(f"TCP tarama başlıyor ({engine}) — {len(hosts)} host, {_MAX_WORKERS} thread, Mod: {mode}")

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
        futures = {
            executor.submit(_scan_host, host, base_name, use_rustscan, full_scan): host
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
    if full_output.is_file() and full_output.stat().st_size > 0:
        logger.info(f"[+] TCP tarama tamamlandı → {full_output}")
    else:
        logger.warning("[!] Birleşik çıktı boş veya oluşturulamadı.")


def _resolve_input(input_file: str) -> Path | None:
    path = Path(input_file) if input_file else ALIVE_HOSTS_FILE
    if not path.is_absolute() and input_file:
        path = SCAN_INPUT_DIR / path
    if not path.is_file():
        logger.error(f"Input dosyası bulunamadı: {path}")
        return None
    return path


def _read_hosts(file_path: Path) -> List[str]:
    try:
        with open(file_path, encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    except OSError as e:
        logger.error(f"Dosya okunamadı: {e}")
        return []


def _scan_host(host: str, base_name: str, use_rustscan: bool, full_scan: bool) -> None:
    out_prefix = str(SCAN_OUTPUT_DIR / f"tcp_{base_name}_{host}")
    if use_rustscan:
        _rustscan_then_nmap(host, out_prefix)
    else:
        _nmap_only(host, out_prefix, full_scan)


def _nmap_only(host: str, out_prefix: str, full_scan: bool) -> None:
    ports = TCP_SCAN_PORTS if full_scan else TCP_FAST_PORTS
    if full_scan:
        nmap_args = [
            "-Pn", "-sVC",
            "--version-intensity", "5",
            "--max-retries", "2",
            "--host-timeout", "240s",
            "-T4", "-p", ports,
            host, "-oA", out_prefix,
        ]
    else:
        nmap_args = [
            "-Pn", "-sV",
            "--version-intensity", "2",
            "--max-retries", "1",
            "--host-timeout", "90s",
            "-T4", "-p", ports,
            host, "-oA", out_prefix,
        ]
    try:
        logger.info(f"  [*] Nmap taranıyor: {host}")
        run_nmap(nmap_args, timeout=SUBPROCESS_TIMEOUT)
        logger.info(f"  [+] Tamamlandı: {host}")
    except FileNotFoundError as e:
        logger.error(str(e))
    except subprocess.TimeoutExpired:
        logger.warning(f"  [!] Timeout ({SUBPROCESS_TIMEOUT}s): {host}")
    except Exception as e:
        logger.error(f"  [!] Nmap hatası ({host}): {e}")


def _rustscan_then_nmap(host: str, out_prefix: str) -> None:
    rustscan_path = get_rustscan_path()
    nmap_path = get_nmap_path()
    if not rustscan_path or not nmap_path:
        logger.warning(f"  [!] RustScan veya Nmap bulunamadı: {host}")
        return

    cmd = [
        rustscan_path, "-a", host, "-b", "1000",
        "--ulimit", "100000", "-r", "0-65535",
        "--", "-Pn", "-sVC", "-oA", out_prefix,
    ]
    try:
        logger.info(f"  [*] RustScan taranıyor: {host}")
        subprocess.run(cmd, shell=False, timeout=SUBPROCESS_TIMEOUT, text=True)
        logger.info(f"  [+] RustScan tamamlandı: {host}")
    except subprocess.TimeoutExpired:
        logger.warning(f"  [!] RustScan timeout: {host}")
    except Exception as e:
        logger.error(f"  [!] RustScan hatası ({host}): {e}")


def _merge_nmap_outputs(base_name: str) -> None:
    nmap_files = sorted(SCAN_OUTPUT_DIR.glob(f"tcp_{base_name}_*.nmap"))
    if not nmap_files:
        logger.warning("Birleştirilecek .nmap dosyası bulunamadı.")
        return

    full_output = SCAN_OUTPUT_DIR / f"tcp_{base_name}_full.txt"
    merged = 0
    try:
        with open(full_output, "w", encoding="utf-8") as out:
            for f in nmap_files:
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore").strip()
                    if content:
                        out.write(content + "\n\n")
                        merged += 1
                except OSError as e:
                    logger.warning(f"Dosya okunamadı ({f.name}): {e}")
    except OSError as e:
        logger.error(f"Birleşik dosya oluşturulamadı: {e}")
        return

    if merged == 0:
        logger.warning("Tüm .nmap dosyaları boş.")
    else:
        logger.info(f"[+] {merged} tarama birleştirildi → {full_output}")