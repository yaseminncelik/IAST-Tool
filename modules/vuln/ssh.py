from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple

from config.settings import SCAN_OUTPUT_DIR, VULN_INPUT_DIR, VULN_OUTPUT_DIR
from core.logger import get_logger
from modules.reports.report_generator import generate_report

logger = get_logger("vuln.ssh")

_SSH_PATTERN    = re.compile(r"(\d+)/tcp\s+open\s+\S*ssh\S*", re.IGNORECASE)
_HOST_PATTERN   = re.compile(r"Nmap scan report for\s+(\S+)")
_BANNER_PATTERN = re.compile(r"\d+/tcp\s+open\s+\S*ssh\S*\s+(.*)", re.IGNORECASE)


def ssh_scan(scan_input: str) -> None:
    VULN_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    target_files = _resolve_targets(scan_input)
    if not target_files:
        return

    all_results: List[Tuple[str, str, str]] = []
    for target in target_files:
        all_results.extend(_parse_ssh_from_nmap(target))

    if not all_results:
        logger.warning("Hiçbir SSH servisi bulunamadı.")
        return

    first_name = Path(target_files[0]).stem
    output_file = VULN_OUTPUT_DIR / f"ssh_{first_name}.txt"
    _save_results(all_results, output_file)
    logger.info(f"[+] {len(all_results)} SSH servisi kaydedildi → {output_file}")

    report_results = [(ip, url) for ip, url, _ in all_results]
    generate_report("SSH Analysis", report_results, scan_input)


def _resolve_targets(scan_input: str) -> List[str]:
    path = Path(scan_input)
    if path.is_dir():
        files = sorted(path.glob("*_full.txt")) or sorted(path.glob("*.nmap"))
        if not files:
            logger.error(f"Scan çıktısı bulunamadı: {path}")
            return []
        logger.info(f"[i] {len(files)} scan çıktısı kullanılıyor.")
        return [str(f) for f in files]
    if path.is_file():
        return [str(path)]
    logger.error(f"Dosya/dizin bulunamadı: {scan_input}")
    return []


def _parse_ssh_from_nmap(file_path: str) -> List[Tuple[str, str, str]]:
    results = []
    current_host = ""
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                m = _HOST_PATTERN.search(line)
                if m:
                    current_host = m.group(1)
                    continue
                m = _SSH_PATTERN.search(line)
                if m and current_host:
                    port = m.group(1)
                    bm = _BANNER_PATTERN.search(line)
                    banner = bm.group(1).strip() if bm else "unknown"
                    url = f"ssh://{current_host}" if port == "22" else f"ssh://{current_host}:{port}"
                    results.append((current_host, url, banner))
                    logger.info(f"  [SSH] {url}  banner: {banner}")
    except OSError as e:
        logger.error(f"Dosya okunamadı ({file_path}): {e}")
    return results


def _save_results(results: List[Tuple[str, str, str]], output_file: Path) -> None:
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            for _, url, banner in results:
                f.write(f"{url}  [{banner}]\n")
    except OSError as e:
        logger.error(f"Sonuçlar yazılamadı: {e}")
