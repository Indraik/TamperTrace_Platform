import time
import datetime
from urllib.parse import urlparse
import vt
from config import Config

class VirusTotalClient:
    """Low-level integration with the VirusTotal API v3 using the official vt-py library."""

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
        return url.rstrip("/").strip().lower()

    @staticmethod
    def is_valid_url(url):
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False

    def fetch_url_analysis(self, url):
        """Fetch existing analysis stats for a URL."""
        if not self.client:
            return None

        url = self.normalize_url(url)
        if not self.is_valid_url(url):
            return None

        try:
            url_id = vt.url_id(url)
            analysis = self.client.get_object(f"/urls/{url_id}")
            stats = analysis.last_analysis_stats
            reputation = getattr(analysis, "reputation", 0)
            scan_date = str(getattr(analysis, "last_analysis_date", datetime.datetime.now()))

            return {
                "stats": stats,
                "reputation": reputation,
                "vt_scan_date": scan_date
            }
        except vt.APIError as e:
            print(f"⚠️ VirusTotal API error for {url}: {e}")
            return None
        except Exception as e:
            print(f"❌ Error fetching VT analysis for {url}: {e}")
            return None

    def submit_for_analysis(self, url):
        """Submit URL for fresh analysis and poll for results."""
        if not self.client:
            return None

        url = self.normalize_url(url)
        try:
            analysis_obj = self.client.scan_url(url)
            # Short wait for completion if possible
            time.sleep(15)
            result = self.client.get_object(f"/analyses/{analysis_obj.id}")
            return {
                "stats": getattr(result, "stats", {}),
                "vt_scan_date": str(getattr(result, "date", datetime.datetime.now())),
                "reputation": 0
            }
        except Exception as e:
            print(f"⚠️ Failed fresh VT analysis submission: {e}")
            # Fall back to existing cached report
            return self.fetch_url_analysis(url)

    def close(self):
        """Safely close underlying HTTP client sessions."""
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
