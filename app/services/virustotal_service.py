import os
import time
import datetime
from urllib.parse import urlparse
import vt
from config import Config
from app.database import get_vt_results_col

class VirusTotalService:
    """Service interfacing with VirusTotal API v3 for URL threat intelligence."""

    def __init__(self, api_key=None):
        self.api_key = api_key or Config.VT_API_KEY
        self.client = None
        if self.api_key:
            try:
                self.client = vt.Client(self.api_key)
            except Exception as e:
                print(f"⚠️ Failed to initialize VirusTotal client: {e}")

    @staticmethod
    def normalize_url(url):
        """Clean and normalize URL for consistent querying."""
        return url.rstrip("/").strip().lower()

    @staticmethod
    def is_valid_url(url):
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False

    def scan_url(self, url, force_rescan=False):
        """Scan a URL using VirusTotal API, utilizing cache if available."""
        if not self.client:
            print("⚠️ VirusTotal client not initialized (missing VT_API_KEY).")
            return None

        url = self.normalize_url(url)
        if not self.is_valid_url(url):
            return None

        vt_results_col = get_vt_results_col()
        current_time = datetime.datetime.now()

        # Check 5-minute cache
        if not force_rescan:
            cached = vt_results_col.find_one({"url": url})
            if cached:
                last_checked = cached.get("last_checked")
                if last_checked and (current_time - last_checked).total_seconds() < 300:
                    return cached

        try:
            url_id = vt.url_id(url)
            analysis = self.client.get_object(f"/urls/{url_id}")
            stats = analysis.last_analysis_stats

            inferred_threats = self._infer_threat_types(stats, url)
            result = {
                "url": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "vt_scan_date": str(analysis.last_analysis_date),
                "last_checked": current_time,
                "reputation": getattr(analysis, "reputation", 0),
                "threat_types": inferred_threats,
                "threat_severity": self.get_threat_severity(stats.get("malicious", 0)),
                "cached_result": False
            }

            vt_results_col.update_one({"url": url}, {"$set": result}, upsert=True)
            return result

        except vt.APIError as e:
            print(f"⚠️ VirusTotal API error for {url}: {e}")
            return None
        except Exception as e:
            print(f"❌ Scan error for {url}: {e}")
            return None

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
        """Unified helper to return safe/suspicious/malicious tag."""
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
        """Retrieve recent scans from database."""
        return list(get_vt_results_col().find().sort("last_checked", -1).limit(limit))

    def close(self):
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass

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
