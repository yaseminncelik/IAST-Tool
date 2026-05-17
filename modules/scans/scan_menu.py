from pathlib import Path

from modules.scans.tcp_scan import tcp_scan
from modules.scans.udp_scan import udp_scan
from config.settings import SCAN_INPUT_DIR, ALIVE_HOSTS_FILE
from core.logger import get_logger
from core.validators import sanitize_filename

logger = get_logger("scans.menu")


def run_scans() -> None:
    print("\n=== SCAN MENU ===")
    print("0 - AUTO       (TCP Hızlı + UDP)")
    print("1 - TCP Hızlı  (yaygın portlar)")
    print("2 - TCP Tam    (0-65535 tüm portlar)")
    print("3 - UDP Scan")

    choice = input("Seçim: ").strip()
    if choice not in ["0", "1", "2", "3"]:
        print("Geçersiz seçim!")
        return

    input_file = _select_input_file()
    if input_file is None:
        return

    try:
        with open(input_file, encoding="utf-8") as f:
            hosts = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    except OSError as e:
        logger.error(f"Dosya okunamadı: {e}")
        return

    if not hosts:
        logger.warning("Dosyada geçerli host bulunamadı.")
        return

    logger.info(f"[i] {len(hosts)} host taranacak.")

    if choice == "0":
        tcp_scan(str(input_file), full_scan=False)
        udp_scan(hosts)
    elif choice == "1":
        tcp_scan(str(input_file), full_scan=False)
    elif choice == "2":
        tcp_scan(str(input_file), full_scan=True)
    elif choice == "3":
        udp_scan(hosts)


def _select_input_file() -> Path | None:
    print("\n[i] Input seçenekleri:")
    print("1 - Discovery çıktısı kullan")
    print("2 - Kendi dosyamı ver")

    choice = input("Seçim: ").strip()

    if choice == "1":
        if not ALIVE_HOSTS_FILE.is_file():
            logger.error(f"Discovery çıktısı bulunamadı: {ALIVE_HOSTS_FILE}")
            logger.info("Önce Host Discovery çalıştırın (Ana Menü → 1).")
            return None
        return ALIVE_HOSTS_FILE

    elif choice == "2":
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

    print("Geçersiz seçim!")
    return None