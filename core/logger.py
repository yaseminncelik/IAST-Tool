import logging
import sys
from pathlib import Path
from datetime import datetime

from config.settings import LOGS_DIR

LOGS_DIR.mkdir(parents=True, exist_ok=True)

_log_file = LOGS_DIR / f"iast_{datetime.now().strftime('%Y%m%d')}.log"

try:
    import colorama
    colorama.init(autoreset=True)
    _COLORS = {
        "DEBUG":    colorama.Fore.CYAN,
        "INFO":     colorama.Fore.GREEN,
        "WARNING":  colorama.Fore.YELLOW,
        "ERROR":    colorama.Fore.RED,
        "CRITICAL": colorama.Fore.MAGENTA,
        "RESET":    colorama.Style.RESET_ALL,
    }
    _HAS_COLOR = True
except ImportError:
    _COLORS = {}
    _HAS_COLOR = False


class _ColorFormatter(logging.Formatter):
    FMT = "[%(levelname)s] %(name)s — %(message)s"

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if _HAS_COLOR:
            color = _COLORS.get(record.levelname, "")
            reset = _COLORS.get("RESET", "")
            return f"{color}{msg}{reset}"
        return msg


def _build_root_logger() -> None:
    root = logging.getLogger("iast")
    if root.handlers:
        return
    root.setLevel(logging.DEBUG)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(_ColorFormatter(_ColorFormatter.FMT))
    root.addHandler(ch)

    fh = logging.FileHandler(_log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root.addHandler(fh)


_build_root_logger()


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"iast.{name}")
