"""
Telnet Zafiyet Analiz Modülü.
Nmap .nmap çıktı dosyalarını Pure Python ile parse ederek
Telnet servislerini tespit eder.
- grep komutu kullanılmaz → Windows uyumlu
- shell=False
- pathlib ile platform bağımsız yollar
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple

from config.settings import SCAN_OUTPUT_DIR, VULN_INPUT_DIR, VULN_OUTPUT_DIR
from core.logger import get_logger
from modules.reports.report_generator import generate_report

logger = get_logger("vuln.telnet")

_TELNET_PATTERN = re.compile(
    r"(\d+)/tcp\s+open\s+\S*telnet\S*",
    re.IGNORECASE,
)

_HOST_PATTERN = re.compile(
    r"Nmap scan report for\s+(\S+)"
)


def telnet_scan(scan_input: str | None = None) -> None:
    """
    scan_input parametresine göre input dosyasını belirler:
      - None veya dizin: scans/outputs altındaki *_full.txt dosyaları
      - Dosya yolu: o dosyayı kullan
    """
    VULN_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    target_files = _resolve_targets(scan_input)
    if not target_files:
        return

    all_results: List[Tuple[str, str]] = []  # (ip, telnet_addr)

    for target in target_files:
        results = _parse_telnet_from_nmap(target)
        all_results.extend(results)

    if not all_results:
        logger.warning("Hiçbir Telnet servisi bulunamadı.")
        return

    first_name = Path(target_files[0]).stem
    output_file = VULN_OUTPUT_DIR / f"telnet_{first_name}.txt"

    _save_results(all_results, output_file)
    logger.info(f"[+] {len(all_results)} Telnet servisi kaydedildi → {output_file}")
    generate_report("Telnet Analysis", all_results, scan_input or str(SCAN_OUTPUT_DIR))


def _resolve_targets(scan_input: str | None) -> List[str]:
    """Input yolunu çözer, taranacak dosya listesini döndürür."""
    if scan_input is None or Path(scan_input).is_dir():
        base = Path(scan_input) if scan_input else SCAN_OUTPUT_DIR
        files = sorted(base.glob("*_full.txt"))
        if not files:
            files = sorted(base.glob("*.nmap"))
        if not files:
            logger.error(f"Scan çıktısı bulunamadı: {base}")
            return []
        logger.info(f"[i] {len(files)} scan çıktısı kullanılıyor.")
        return [str(f) for f in files]

    path = Path(scan_input)
    if path.is_file():
        return [str(path)]

    alt_path = VULN_INPUT_DIR / scan_input
    if alt_path.is_file():
        return [str(alt_path)]

    logger.error(f"Dosya/dizin bulunamadı: {scan_input}")
    return []


def _parse_telnet_from_nmap(file_path: str) -> List[Tuple[str, str]]:
    """
    Nmap çıktı dosyasını okuyarak Telnet servislerini bulur.
    Döndürür: [(ip, telnet_addr), ...]
    """
    results = []
    current_host = ""

    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()

                host_match = _HOST_PATTERN.search(line)
                if host_match:
                    current_host = host_match.group(1)
                    continue

                telnet_match = _TELNET_PATTERN.search(line)
                if telnet_match and current_host:
                    port = telnet_match.group(1)
                    addr = f"telnet://{current_host}:{port}"
                    results.append((current_host, addr))
                    logger.info(f"  [TELNET] {addr}")

    except OSError as e:
        logger.error(f"Dosya okunamadı ({file_path}): {e}")

    return results


def _save_results(results: List[Tuple[str, str]], output_file: Path) -> None:
    """Sonuçları TXT dosyasına yazar."""
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            for ip, addr in results:
                f.write(f"{addr}\n")
    except OSError as e:
        logger.error(f"Sonuçlar yazılamadı: {e}")