"""
Bağımlılık kontrol modülü.
Başlangıçta gerekli araçları ve kütüphaneleri kontrol eder.
"""

from core.platform_utils import IS_WINDOWS, get_nmap_path, get_rustscan_path, find_tool
from core.logger import get_logger

logger = get_logger("dependency_checker")


def check_nmap() -> bool:
    """Nmap kurulu mu kontrol eder."""
    path = get_nmap_path()
    if path:
        logger.info(f"[✓] Nmap bulundu: {path}")
        return True
    logger.warning(
        "[✗] Nmap bulunamadı!\n"
        "      Windows: https://nmap.org/download.html\n"
        "      Linux:   sudo apt install nmap"
    )
    return False


def check_npcap() -> bool:
    """
    Windows'ta Npcap kurulu mu kontrol eder.
    (Nmap raw socket taramaları için gereklidir.)
    """
    if not IS_WINDOWS:
        return True  # Linux'ta gerekmez

    try:
        import winreg
        key_paths = [
            r"SOFTWARE\Npcap",
            r"SOFTWARE\WOW6432Node\Npcap",
        ]
        for key_path in key_paths:
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                logger.info("[✓] Npcap kurulu.")
                return True
            except FileNotFoundError:
                continue
    except Exception:
        pass

    import shutil
    if shutil.which("npcap") or shutil.which("wpcap"):
        logger.info("[✓] Npcap (alternatif kontrol) kurulu.")
        return True

    logger.warning(
        "[✗] Npcap bulunamadı! Raw socket taramaları çalışmayabilir.\n"
        "      İndir: https://npcap.com/#download"
    )
    return False


def check_rustscan() -> bool:
    """RustScan kurulu mu kontrol eder (Linux opsiyonel)."""
    if IS_WINDOWS:
        return False  # Windows'ta kullanılmıyor

    path = get_rustscan_path()
    if path:
        logger.info(f"[✓] RustScan bulundu: {path}")
        return True
    logger.info("[i] RustScan bulunamadı. TCP tarama Nmap ile yapılacak.")
    return False


def check_python_packages() -> dict:
    """
    Opsiyonel Python paketlerini kontrol eder.
    Eksikler uyarı olarak gösterilir, kritik değil.
    """
    packages = {
        "rich":      "Gelişmiş terminal UI",
        "colorama":  "Windows terminal renk desteği",
    }
    results = {}
    for pkg, desc in packages.items():
        try:
            __import__(pkg)
            results[pkg] = True
            logger.info(f"[✓] {pkg} ({desc})")
        except ImportError:
            results[pkg] = False
            logger.info(f"[i] {pkg} yok ({desc}) — pip install {pkg}")
    return results


def run_all_checks() -> bool:
    """
    Tüm bağımlılıkları kontrol eder.
    Kritik eksiklik varsa False döndürür.
    """
    print("\n" + "="*50)
    print("  Bağımlılık Kontrolü")
    print("="*50)

    nmap_ok    = check_nmap()
    npcap_ok   = check_npcap()
    check_rustscan()
    check_python_packages()

    print("="*50 + "\n")

    if not nmap_ok:
        logger.error("Nmap kurulu olmadan araç çalışamaz!")
        return False

    if IS_WINDOWS and not npcap_ok:
        logger.warning("Npcap olmadan raw socket taramaları başarısız olabilir.")

    return True
