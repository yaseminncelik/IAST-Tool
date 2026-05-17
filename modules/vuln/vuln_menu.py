from __future__ import annotations

from pathlib import Path

from config.settings import SCAN_OUTPUT_DIR, VULN_INPUT_DIR
from modules.vuln.ftp import ftp_scan
from modules.vuln.telnet import telnet_scan
from modules.vuln.ssh import ssh_scan
from core.logger import get_logger
from core.validators import sanitize_filename

logger = get_logger("vuln.menu")


def run_vuln() -> None:
    print("\n=== VULNERABILITY MENU ===")
    print("1 - FTP Analysis")
    print("2 - Telnet Analysis")
    print("3 - SSH Analysis")

    choice = input("Seçim: ").strip()
    if choice not in ["1", "2", "3"]:
        print("Geçersiz seçim!")
        return

    scan_input = _select_input_source()
    if scan_input is None:
        return

    if choice == "1":
        ftp_scan(scan_input)
    elif choice == "2":
        telnet_scan(scan_input)
    elif choice == "3":
        ssh_scan(scan_input)


def _select_input_source() -> str | None:
    print("\n[i] Input seçenekleri:")
    print("1 - Scan outputs kullan")
    print("2 - Kendi dosyamı ver")

    choice = input("Seçim: ").strip()

    if choice == "1":
        if not SCAN_OUTPUT_DIR.is_dir():
            logger.error(f"Scan çıktı dizini bulunamadı: {SCAN_OUTPUT_DIR}")
            logger.info("Önce TCP Scan çalıştırın (Ana Menü → 2).")
            return None
        scan_files = list(SCAN_OUTPUT_DIR.glob("*_full.txt")) + list(SCAN_OUTPUT_DIR.glob("*.nmap"))
        if not scan_files:
            logger.error("Scan çıktı dizini boş — önce TCP Scan çalıştırın (Ana Menü → 2).")
            return None
        logger.info(f"[i] {len(scan_files)} scan çıktı dosyası bulundu.")
        return str(SCAN_OUTPUT_DIR)

    elif choice == "2":
        logger.info(f"Dosyanı şu dizine koy: {VULN_INPUT_DIR}")
        raw_name = input("Dosya adı: ").strip()
        if not raw_name:
            print("Dosya adı boş olamaz!")
            return None
        try:
            safe_name = sanitize_filename(raw_name)
        except ValueError as e:
            logger.error(f"Geçersiz dosya adı: {e}")
            return None
        file_path = VULN_INPUT_DIR / safe_name
        if not file_path.is_file():
            logger.error(f"Dosya bulunamadı: {file_path}")
            return None
        return str(file_path)

    print("Geçersiz seçim!")
    return None