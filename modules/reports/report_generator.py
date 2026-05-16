"""
JSON Rapor Üretici Modülü.
Zafiyet analizi sonuçlarını JSON formatında kaydeder.
"""

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
    """
    Zafiyet analizi bulgularını JSON raporu olarak kaydeder.

    Args:
        scan_type:     Analiz türü (örn. "FTP Analysis", "Telnet Analysis")
        findings:      [(ip, url), ...] formatında bulgular listesi
        target_source: Analiz edilen kaynak dosya/dizin yolu

    Returns:
        Oluşturulan rapor dosyasının Path'i, başarısız olursa None.
    """
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
    """Ham (ip, url) tuple listesini yapılandırılmış finding dict listesine çevirir."""
    result = []
    for ip, url in findings:
        service = _detect_service(scan_type)
        port = _extract_port(url, service)
        result.append({
            "ip": ip,
            "service": service,
            "url": url,
            "port": port,
            "risk": _assess_risk(service),
        })
    return result


def _detect_service(scan_type: str) -> str:
    """Scan türünden servis adını çıkarır."""
    scan_type_lower = scan_type.lower()
    if "ftp" in scan_type_lower:
        return "FTP"
    if "telnet" in scan_type_lower:
        return "Telnet"
    return "Unknown"


def _extract_port(url: str, service: str) -> int:
    """URL'den port numarasını çıkarır; bulunamazsa servis varsayılanını döndürür."""
    defaults = {"FTP": 21, "Telnet": 23}
    try:
        if ":" in url.split("//")[-1]:
            return int(url.split(":")[-1])
    except (ValueError, IndexError):
        pass
    return defaults.get(service, 0)


def _assess_risk(service: str) -> str:
    """Servis türüne göre risk seviyesi belirler."""
    high_risk = {"FTP", "Telnet"}
    if service in high_risk:
        return "HIGH"
    return "MEDIUM"
