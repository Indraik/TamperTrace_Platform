"""
Legacy compatibility wrapper for virustotal_scanner.py.
Implementation has been refactored into app.integrations.virustotal and app.services.virustotal_service.
"""
from app.services.virustotal_service import (
    VirusTotalService,
    get_vt_scanner,
    scan_single_url,
    get_scan_history,
    get_threat_level
)

VirusTotalScanner = VirusTotalService

__all__ = [
    "VirusTotalService",
    "VirusTotalScanner",
    "get_vt_scanner",
    "scan_single_url",
    "get_scan_history",
    "get_threat_level"
]