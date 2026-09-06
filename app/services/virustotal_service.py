import datetime
from app.integrations.virustotal import VirusTotalClient
from app.repositories.threat_repository import ThreatRepository

class VirusTotalService:
    """Domain service managing URL threat scanning, categorization, and cache policies."""

    def __init__(self, api_key=None):
        self.client = VirusTotalClient(api_key=api_key)

    @staticmethod
    def normalize_url(url):
        return VirusTotalClient.normalize_url(url)

    @staticmethod
    def is_valid_url(url):
        return VirusTotalClient.is_valid_url(url)

    def scan_url(self, url, force_rescan=False):
        """Scan URL via VirusTotal client with 5-minute database cache."""
        url = self.normalize_url(url)
        if not self.is_valid_url(url):
            return None

        current_time = datetime.datetime.now()

        # Check 5-minute cache unless force requested
        if not force_rescan:
            cached = ThreatRepository.get_by_url(url)
            if cached:
                last_checked = cached.get("last_checked")
                if last_checked and (current_time - last_checked).total_seconds() < 300:
                    return cached

        # Fetch from VirusTotal integration
        if force_rescan:
            analysis_data = self.client.submit_for_analysis(url)
        else:
            analysis_data = self.client.fetch_url_analysis(url)

        if not analysis_data or not analysis_data.get("stats"):
            return None

        stats = analysis_data["stats"]
        inferred_threats = self._infer_threat_types(stats, url)

        result = {
            "url": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()),
            "vt_scan_date": analysis_data.get("vt_scan_date", str(current_time)),
            "last_checked": current_time,
            "scan_date": current_time,
            "reputation": analysis_data.get("reputation", 0),
            "threat_types": inferred_threats,
            "threat_severity": self.get_threat_severity(stats.get("malicious", 0)),
            "cached_result": False
        }

        # Save to database repository
        ThreatRepository.save_scan_result(result)
        return result

    @staticmethod
    def _infer_threat_types(stats, url):
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        url_lower = url.lower()
        threats = []

        if malicious >= 20:
            threats.append("🚨 WIDESPREAD MALWARE")
        elif malicious >= 10:
            threats.append("🔥 CONFIRMED MALWARE")
        elif malicious >= 5:
            threats.append("⚠️ MULTIPLE DETECTIONS")
        elif malicious >= 1:
            threats.append("🔶 SUSPICIOUS CONTENT")

        if any(p in url_lower for p in ['login', 'signin', 'verify', 'account', 'bank']):
            if malicious >= 3:
                threats.append("🎯 PHISHING RISK")
            elif suspicious >= 5:
                threats.append("🔐 SUSPICIOUS LOGIN")

        if any(p in url_lower for p in ['crypto', 'bitcoin', 'mining', 'coin']):
            threats.append("⛏️ CRYPTO MINING RISK")

        if any(p in url_lower for p in ['crack', 'keygen', 'serial', 'torrent']):
            threats.append("⚖️ PIRATED SOFTWARE")

        if any(p in url_lower for p in ['free', 'download', 'offer', 'win']) and malicious >= 2:
            threats.append("📥 MALICIOUS DOWNLOAD")

        if malicious >= 15:
            threats.append("🦠 ADVANCED MALWARE")
        elif malicious >= 8:
            threats.append("📛 KNOWN THREAT")

        if not threats and (malicious > 0 or suspicious > 0):
            threats.append("⚠️ SUSPICIOUS BEHAVIOR")

        return threats

    @staticmethod
    def get_threat_severity(malicious_count):
        if malicious_count >= 10:
            return "CRITICAL"
        elif malicious_count >= 5:
            return "HIGH"
        elif malicious_count >= 1:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def get_threat_level(result_or_count):
        """Standardized threat level tag for dashboard badges."""
        if isinstance(result_or_count, dict):
            malicious = result_or_count.get("malicious", 0)
            suspicious = result_or_count.get("suspicious", 0)
        else:
            malicious = result_or_count or 0
            suspicious = 0

        if malicious > 0:
            return "malicious"
        elif suspicious > 0:
            return "suspicious"
        return "safe"

    @staticmethod
    def get_scan_history(limit=10):
        return ThreatRepository.get_recent_scans(limit=limit)

    def close(self):
        self.client.close()

# Module-level convenience functions
_scanner_instance = None

def get_vt_scanner():
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = VirusTotalService()
    return _scanner_instance

def scan_single_url(url):
    scanner = get_vt_scanner()
    return scanner.scan_url(url)

def get_threat_level(result_or_count):
    return VirusTotalService.get_threat_level(result_or_count)

def get_scan_history(limit=10):
    return VirusTotalService.get_scan_history(limit)
