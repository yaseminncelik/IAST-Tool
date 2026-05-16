"""
Tarama Menüsü.
TCP, UDP veya AUTO (TCP+UDP) tarama modlarını yönetir.
"""

from pathlib import Path

from modules.scans.tcp_scan import tcp_scan
from modules.scans.udp_scan import udp_scan
from config.settings import SCAN_INPUT_DIR, ALIVE_HOSTS_FILE
from core.logger import get_logger
from core.validators import sanitize_filename

logger = get_logger("scans.menu")


def run_scans() -> None:
    """Ana tarama menüsünü çalıştırır."""

    print("\n=== SCAN MENU ===")
    print("0 - AUTO (TCP + UDP)")
    print("1 - TCP Scan")
    print("2 - UDP Scan")

    choice = input("Seçim: ").strip()

    if choice not in ["0", "1", "2"]:
        print("Geçersiz seçim!")
        return

    input_file = _select_input_file()
    if input_file is None:
        return

    try:
        with open(input_file, encoding="utf-8") as f:
            hosts = [h.strip() for h in f if h.strip()]
    except OSError as e:
        logger.error(f"Dosya okunamadı: {e}")
        return

    if not hosts:
        logger.warning("Dosyada geçerli host bulunamadı.")
        return

    if choice == "0":
        logger.info("AUTO MODE — TCP + UDP")
        tcp_scan(str(input_file))
        udp_scan(hosts)

    elif choice == "1":
        tcp_scan(str(input_file))

    elif choice == "2":
        udp_scan(hosts)


def _select_input_file() -> Path | None:
    """Kullanıcıdan input dosyası seçimini alır."""
    print("\n[i] Input seçenekleri:")
    print("1 - Discovery çıktısı kullan")
    print("2 - Kendi dosyamı ver")

    input_choice = input("Seçim: ").strip()

    if input_choice == "1":
        if not ALIVE_HOSTS_FILE.is_file():
            logger.error(f"Discovery çıktısı bulunamadı: {ALIVE_HOSTS_FILE}")
            logger.info("Önce Host Discovery çalıştırın (Ana Menü → 1).")
            return None
        return ALIVE_HOSTS_FILE

    elif input_choice == "2":
        logger.info(f"Dosyanı şu dizine koy: {SCAN_INPUT_DIR}")
        raw_name = input("Dosya adı: ").strip()

        if not raw_name:
            print("Dosya adı boş olamaz!")
            return None

        try:
            safe_name = sanitize_filename(raw_name)
        except ValueError as e:
            logger.error(f"Geçersiz dosya adı: {e}")
            return None

        file_path = SCAN_INPUT_DIR / safe_name

        if not file_path.is_file():
            logger.error(f"Dosya bulunamadı: {file_path}")
            return None
        return file_path

    else:
        print("Geçersiz seçim!")
        return None