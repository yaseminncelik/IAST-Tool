"""
FTP Zafiyet Analiz Modülü.
Nmap .nmap çıktı dosyalarını Pure Python ile parse ederek
FTP servislerini tespit eder.
- AWK komutu kullanılmaz → Windows uyumlu
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

logger = get_logger("vuln.ftp")

# Nmap çıktısında açık FTP portunu bulmak için pattern
# Örnek satır: "21/tcp   open  ftp   vsftpd 3.0.3"
_FTP_PATTERN = re.compile(
    r"(\d+)/tcp\s+open\s+\S*ftp\S*",
    re.IGNORECASE,
)

# Mevcut host satırını bulmak için pattern
# Örnek: "Nmap scan report for 10.0.0.1"
_HOST_PATTERN = re.compile(
    r"Nmap scan report for\s+(\S+)"
)


def ftp_scan(scan_input: str) -> None:
    """
    scan_input parametresine göre input dosyasını belirler:
      - Dizin yolu: o dizindeki *_full.txt dosyalarını kullan
      - Dosya yolu: o dosyayı kullan
    """
    VULN_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    target_files = _resolve_targets(scan_input)
    if not target_files:
        return

    all_results: List[Tuple[str, str]] = []  # (ip, ftp_url)

    for target in target_files:
        results = _parse_ftp_from_nmap(target)
        all_results.extend(results)

    if not all_results:
        logger.warning("Hiçbir FTP servisi bulunamadı.")
        return

    # İlk hedef dosyanın adını kullan
    first_name = Path(target_files[0]).stem
    output_file = VULN_OUTPUT_DIR / f"ftp_{first_name}.txt"

    _save_results(all_results, output_file)
    logger.info(f"[+] {len(all_results)} FTP servisi kaydedildi → {output_file}")
    generate_report("FTP Analysis", all_results, scan_input)


def _resolve_targets(scan_input: str) -> List[str]:
    """Input yolunu çözer, taranacak dosya listesini döndürür."""
    path = Path(scan_input)

    if path.is_dir():
        files = sorted(path.glob("*_full.txt"))
        if not files:
            files = sorted(path.glob("*.nmap"))

        if not files:
            logger.error(f"Scan çıktısı bulunamadı: {path}")
            return []
        logger.info(f"[i] {len(files)} scan çıktısı kullanılıyor: {path}")
        return [str(f) for f in files]

    if path.is_file():
        return [str(path)]

    logger.error(f"Dosya/dizin bulunamadı: {scan_input}")
    return []


def _parse_ftp_from_nmap(file_path: str) -> List[Tuple[str, str]]:
    """
    Nmap .nmap / full.txt dosyasını okuyarak FTP servislerini bulur.
    Döndürür: [(ip, ftp_url), ...]
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

                ftp_match = _FTP_PATTERN.search(line)
                if ftp_match and current_host:
                    port = ftp_match.group(1)
                    if port == "21":
                        url = f"ftp://{current_host}"
                    else:
                        url = f"ftp://{current_host}:{port}"
                    results.append((current_host, url))
                    logger.info(f"  [FTP] {url}")

    except OSError as e:
        logger.error(f"Dosya okunamadı ({file_path}): {e}")

    return results


def _save_results(results: List[Tuple[str, str]], output_file: Path) -> None:
    """Sonuçları TXT dosyasına yazar."""
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            for ip, url in results:
                f.write(f"{url}\n")
    except OSError as e:
        logger.error(f"Sonuçlar yazılamadı: {e}")