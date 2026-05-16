"""
Merkezi konfigürasyon modülü.
Tüm dizin yolları ve tarama parametreleri buradan yönetilir.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

MODULES_DIR       = BASE_DIR / "modules"
LOGS_DIR          = BASE_DIR / "logs"

DISCOVERY_DIR     = MODULES_DIR / "discovery"
SCAN_DIR          = MODULES_DIR / "scans"
VULN_DIR          = MODULES_DIR / "vuln"
OUTPUTS_DIR       = MODULES_DIR / "outputs"

SCAN_INPUT_DIR    = SCAN_DIR / "inputs"
SCAN_OUTPUT_DIR   = SCAN_DIR / "outputs"
VULN_INPUT_DIR    = VULN_DIR / "inputs"
VULN_OUTPUT_DIR   = VULN_DIR / "outputs"

ALIVE_HOSTS_FILE  = SCAN_INPUT_DIR / "alive_hosts.txt"
DISCOVERY_GNMAP   = OUTPUTS_DIR / "discovery.gnmap"

DISCOVERY_PORTS_TCP = "21,22,23,25,53,80,88,111,135,139,443,445,1433,3306,3389,5900,8080,6379,9100"
DISCOVERY_PORTS_ACK = "80,443"

TCP_SCAN_PORTS    = "0-65535"
UDP_COMMON_PORTS  = "53,67,68,69,111,123,137,138,161,162,500,514,1900,4500"

SUBPROCESS_TIMEOUT = 600

APP_NAME    = "IAST Tool"
APP_VERSION = "2.0.0"
APP_AUTHOR  = "Internal Pen-Test Suite"

REPORTS_DIR = BASE_DIR / "modules" / "reports" / "outputs"
