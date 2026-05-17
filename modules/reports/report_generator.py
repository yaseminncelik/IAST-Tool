from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

from config.settings import APP_NAME, APP_VERSION, REPORTS_DIR
from core.logger import get_logger

logger = get_logger("reports")


def generate_report(
    scan_type: str,
    findings: List[Tuple[str, str]],
    target_source: str,
) -> Path | None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now()
    filename = f"report_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
    output_path = REPORTS_DIR / filename

    unique_hosts = list({ip for ip, _ in findings})

    report = {
        "tool": f"{APP_NAME} v{APP_VERSION}",
        "generated_at": timestamp.isoformat(timespec="seconds"),
        "scan_type": scan_type,
        "target_source": target_source,
        "findings": _build_findings(scan_type, findings),
        "summary": {
            "total_findings": len(findings),
            "unique_hosts": len(unique_hosts),
        },
    }

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logger.info(f"[+] JSON rapor kaydedildi → {output_path}")
        return output_path
    except OSError as e:
        logger.error(f"Rapor yazılamadı: {e}")
        return None


def _build_findings(scan_type: str, findings: List[Tuple[str, str]]) -> list:
    return [
        {
            "ip": ip,
            "service": _detect_service(scan_type),
            "url": url,
            "port": _extract_port(url, _detect_service(scan_type)),
            "risk": _assess_risk(_detect_service(scan_type)),
        }
        for ip, url in findings
    ]


def _detect_service(scan_type: str) -> str:
    t = scan_type.lower()
    if "ftp" in t:
        return "FTP"
    if "telnet" in t:
        return "Telnet"
    if "ssh" in t:
        return "SSH"
    return "Unknown"


def _extract_port(url: str, service: str) -> int:
    defaults = {"FTP": 21, "SSH": 22, "Telnet": 23}
    try:
        if ":" in url.split("//")[-1]:
            return int(url.split(":")[-1])
    except (ValueError, IndexError):
        pass
    return defaults.get(service, 0)


def _assess_risk(service: str) -> str:
    if service in {"FTP", "Telnet"}:
        return "HIGH"
    if service == "SSH":
        return "MEDIUM"
    return "LOW"
