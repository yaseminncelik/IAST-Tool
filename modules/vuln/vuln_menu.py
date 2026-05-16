"""
Zafiyet Analiz Menüsü.
FTP ve Telnet analiz modüllerini yönetir.
"""

from pathlib import Path

from modules.vuln.ftp import ftp_scan
from modules.vuln.telnet import telnet_scan
from config.settings import SCAN_OUTPUT_DIR, VULN_INPUT_DIR
from core.logger import get_logger
from core.validators import sanitize_filename

logger = get_logger("vuln.menu")


def run_vuln() -> None:
    """Ana zafiyet analiz menüsünü çalıştırır."""

    print("\n=== VULNERABILITY MENU ===")
    print("1 - FTP Analysis")
    print("2 - Telnet Analysis")

    choice = input("Seçim: ").strip()

    if choice not in ["1", "2"]:
        print("Geçersiz seçim!")
        return

    scan_input = _select_input_source()
    if scan_input is None:
        return

    if choice == "1":
        ftp_scan(scan_input)

    elif choice == "2":
        telnet_scan(scan_input)


def _select_input_source() -> str | None:
    """Kullanıcıdan scan input kaynağını seçmesini ister."""
    print("\n[i] Input seçenekleri:")
    print("1 - Scan outputs kullan (varsayılan)")
    print("2 - Kendi dosyamı ver")

    input_choice = input("Seçim: ").strip()

    if input_choice == "1":
        if not SCAN_OUTPUT_DIR.is_dir():
            logger.error(f"Scan çıktı dizini bulunamadı: {SCAN_OUTPUT_DIR}")
            logger.info("Önce TCP/UDP Scan çalıştırın (Ana Menü → 2).")
            return None
        return str(SCAN_OUTPUT_DIR)

    elif input_choice == "2":
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

    else:
        print("Geçersiz seçim!")
        return None