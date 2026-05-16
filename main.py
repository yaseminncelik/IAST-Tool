"""
IAST Tool — Internal Assessment & Scanning Toolkit
Ana giriş noktası.

Akış: Host Discovery → Scan (TCP/UDP) → Vulnerability Analysis
"""

from __future__ import annotations

from modules.discovery.host_discovery import run_discovery
from modules.scans.scan_menu import run_scans
from modules.vuln.vuln_menu import run_vuln
from core.platform_utils import get_platform_info, check_admin
from core.dependency_checker import run_all_checks
from core.validators import validate_ip_range
from config.settings import APP_NAME, APP_VERSION

try:
    from rich.console import Console  # type: ignore
    from rich.panel import Panel       # type: ignore
    from rich.table import Table       # type: ignore
    from rich.text import Text         # type: ignore
    from rich import box               # type: ignore
    _console = Console()
    _HAS_RICH = True
except ImportError:
    _console = None
    _HAS_RICH = False


def _print_banner() -> None:
    """Uygulama başlık banner'ını yazdırır."""
    if _HAS_RICH:
        info = get_platform_info()
        admin = "✓ Yönetici" if check_admin() else "✗ Standart Kullanıcı"

        banner = Text()
        banner.append(f"\n  {APP_NAME}  ", style="bold cyan")
        banner.append(f"v{APP_VERSION}\n", style="dim white")
        banner.append("  Internal Penetration Testing Toolkit\n", style="italic dim")

        details = (
            f"  OS: {info['os']} {info['release']}  |  "
            f"Python: {info['python']}  |  "
            f"Yetki: {admin}"
        )

        assert _console is not None
        _console.print(
            Panel(
                banner,
                subtitle=details,
                border_style="cyan",
                expand=False,
                padding=(0, 2),
            )
        )
    else:
        print("\n" + "=" * 50)
        print(f"  {APP_NAME} v{APP_VERSION}")
        print("  Internal Penetration Testing Toolkit")
        print("=" * 50)
        info = get_platform_info()
        admin = "Yönetici" if check_admin() else "Standart Kullanıcı"
        print(f"  OS: {info['os']} {info['release']} | Python: {info['python']} | Yetki: {admin}")
        print("=" * 50)


def _print_menu() -> None:
    """Ana menüyü yazdırır."""
    if _HAS_RICH:
        table = Table(
            show_header=False,
            box=box.ROUNDED,
            border_style="dim cyan",
            padding=(0, 2),
            expand=False,
        )
        table.add_column("key",  style="bold yellow", width=4)
        table.add_column("desc", style="white")

        table.add_row("1", "Host Discovery")
        table.add_row("2", "Scans  (TCP / UDP / AUTO)")
        table.add_row("3", "Vulnerability Analysis")
        table.add_row("─", "─" * 24)
        table.add_row("0", "Exit")

        assert _console is not None
        _console.print("\n")
        _console.print(table)
    else:
        print("\n=== MAIN MENU ===")
        print("1 - Host Discovery")
        print("2 - Scans")
        print("3 - Vulnerability Analysis")
        print("0 - Exit")


def main() -> None:
    _print_banner()

    # Bağımlılık kontrolü — Nmap eksikse uyar ama devam et
    run_all_checks()

    while True:
        _print_menu()
        choice = input("\nSeçim: ").strip()

        if choice == "1":
            ip_range = input("IP Range (örn: 192.168.1.0/24): ").strip()
            if not ip_range:
                print("IP Range boş olamaz!")
                continue
            if not validate_ip_range(ip_range):
                print(f"Geçersiz IP/CIDR formatı: '{ip_range}'")
                continue
            run_discovery(ip_range)

        elif choice == "2":
            run_scans()

        elif choice == "3":
            print("[i] Not: Vulnerability analizi için önce scan çıktısı gereklidir.")
            run_vuln()

        elif choice == "0":
            print("\nÇıkılıyor...")
            break

        else:
            print("Geçersiz seçim!")


if __name__ == "__main__":
    main()