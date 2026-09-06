import os
import time
import vt
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from pymongo import MongoClient
from dotenv import load_dotenv
import datetime

# ✅ Load environment variables securely
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["tampertrace"]
vt_results_collection = db["vt_scan_results"]
monitored_urls_collection = db["monitored_urls"]
def normalize_url(url):
        return url.rstrip("/").strip().lower()
class VirusTotalScanner:

    def __init__(self, api_key=None):
        if not api_key:
            api_key = os.getenv("VT_API_KEY")
        if not api_key:
            raise ValueError("VirusTotal API key not found. Please set VT_API_KEY in .env file")
        
        self.client = vt.Client(api_key)
        print("✅ VirusTotal scanner initialized securely")

    def scan_url(self, url, force_rescan=False):
        """Scan a URL using VirusTotal API"""
        url = normalize_url(url)
        try:
            print(f"🔍 Scanning URL: {url}")

            if not self._is_valid_url(url):
             print(f"⚠️ Skipping invalid URL: {url}")
             return None

            current_time = datetime.datetime.now()

            # 🔁 FORCE RESCAN
            if force_rescan:
                print("🔄 Force rescan requested")
                result = self._submit_new_analysis(url)
                if result:
                    result["last_checked"] = current_time
                return result

            # 🧠 CHECK CACHE
            existing = vt_results_collection.find_one({"url": url})
            if existing:
                last_checked = existing.get("last_checked")
                if last_checked and (current_time - last_checked).seconds < 300:
                    print("⏭️ Using cached result")

                    
            # 🌐 FETCH FROM VIRUSTOTAL
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
                "reputation": analysis.reputation if hasattr(analysis, "reputation") else 0,
                "threat_types": inferred_threats,
                "threat_severity": self._get_threat_severity(stats.get("malicious", 0)),
                "cached_result": False
            }

            # 💾 SAVE VT RESULT
            vt_results_collection.update_one(
                {"url": url},
                {"$set": result},
                upsert=True
            )

            

            print(
                f"✅ Scan done → "
                f"Malicious: {result['malicious']} | "
                f"Suspicious: {result['suspicious']} | "
                f"Threat: {self._get_threat_level(result)}"
            )

            return result

        except vt.APIError as e:
            print(f"⚠️ VirusTotal API Error: {e}")
            return None

        except Exception as e:
            print(f"❌ Scan error for {url}: {e}")
            return None


    def _infer_threat_types(self, stats, url):
        """Infer threat types based on vendor counts and URL patterns"""
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        url_lower = url.lower()
        
        threats = []
        
        # High confidence based on vendor counts
        if malicious >= 20:
            threats.append("🚨 WIDESPREAD MALWARE")
        elif malicious >= 10:
            threats.append("🔥 CONFIRMED MALWARE")
        elif malicious >= 5:
            threats.append("⚠️ MULTIPLE DETECTIONS")
        elif malicious >= 1:
            threats.append("🔶 SUSPICIOUS CONTENT")
        
        # URL pattern analysis
        if any(pattern in url_lower for pattern in ['login', 'signin', 'verify', 'account', 'bank']):
            if malicious >= 3:
                threats.append("🎯 PHISHING RISK")
            elif suspicious >= 5:
                threats.append("🔐 SUSPICIOUS LOGIN")
        
        if any(pattern in url_lower for pattern in ['crypto', 'bitcoin', 'mining', 'coin']):
            threats.append("⛏️ CRYPTO MINING RISK")
        
        if any(pattern in url_lower for pattern in ['crack', 'keygen', 'serial', 'torrent']):
            threats.append("⚖️ PIRATED SOFTWARE")
        
        if any(pattern in url_lower for pattern in ['free', 'download', 'offer', 'win']):
            if malicious >= 2:
                threats.append("📥 MALICIOUS DOWNLOAD")
        
        # Generic classifications
        if malicious >= 15:
            threats.append("🦠 ADVANCED MALWARE")
        elif malicious >= 8:
            threats.append("📛 KNOWN THREAT")
        
        if not threats and (malicious > 0 or suspicious > 0):
            threats.append("🔍 GENERIC THREAT")
        
        return threats if threats else ["✅ CLEAN"]

    def _get_threat_severity(self, malicious_count):
        """Get threat severity based on malicious count"""
        if malicious_count >= 20:
            return "CRITICAL"
        elif malicious_count >= 10:
            return "HIGH"
        elif malicious_count >= 5:
            return "MEDIUM"
        elif malicious_count >= 1:
            return "LOW"
        else:
            return "CLEAN"

    def _submit_new_analysis(self, url):
        """Submit URL for new analysis (force fresh scan)"""
        try:
            print(f"📤 Submitting new analysis for: {url}")
            analysis = self.client.scan_url(url)
            
            # Wait for analysis (respect rate limits)
            print("⏳ Waiting 20 seconds for analysis completion...")
            time.sleep(20)
            
            analysis_result = self.client.get_object(f"/analyses/{analysis.id}")
            stats = analysis_result.stats
            
            # Get inferred threat types
            inferred_threats = self._infer_threat_types(stats, url)
            
            result = {
                "url": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "vt_scan_date": str(analysis_result.date),  # VirusTotal's scan date
                "last_checked": datetime.datetime.now(),    # ✅ OUR current timestamp
                "reputation": 0,
                "threat_types": inferred_threats,
                "threat_severity": self._get_threat_severity(stats.get("malicious", 0)),
                "submitted": True,
                "cached_result": False
            }
            
            vt_results_collection.update_one(
                {"url": url},
                {"$set": result},
                upsert=True
            )
            
            print(f"✅ New analysis completed: {result['malicious']} malicious, {len(inferred_threats)} threat types")
            return result
            
        except Exception as e:
            print(f"❌ Error submitting analysis: {e}")
            return None
    

    def _is_valid_url(self, url):
        """Validate URL format"""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False

    def _get_threat_level(self, result):
        """Determine threat level"""
        malicious = result.get('malicious', 0)
        suspicious = result.get('suspicious', 0)
        
        if malicious >= 5:
            return "high"
        elif malicious >= 2:
            return "medium" 
        elif malicious >= 1 or suspicious >= 3:
            return "low"
        else:
            return "clean"

    def extract_external_resources(self, html_content, base_url):
        """Extract external scripts, iframes, and links from HTML"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            external_urls = set()
            
            # Extract external scripts
            for script in soup.find_all('script', src=True):
                full_url = urljoin(base_url, script['src'])
                if self._is_external_domain(full_url, base_url):
                    external_urls.add(full_url)
            
            # Extract external iframes
            for iframe in soup.find_all('iframe', src=True):
                full_url = urljoin(base_url, iframe['src'])
                if self._is_external_domain(full_url, base_url):
                    external_urls.add(full_url)
            
            # Extract external links
            for link in soup.find_all('a', href=True):
                full_url = urljoin(base_url, link['href'])
                if self._is_external_domain(full_url, base_url):
                    external_urls.add(full_url)
            
            print(f"🔍 Found {len(external_urls)} external resources")
            return list(external_urls)
            
        except Exception as e:
            print(f"❌ Error extracting resources: {e}")
            return []

    def _is_external_domain(self, url, base_url):
        """Check if URL is from external domain"""
        try:
            url_domain = urlparse(url).netloc
            base_domain = urlparse(base_url).netloc
            return url_domain and url_domain != base_domain
        except:
            return False

    def close(self):
        """Close VirusTotal client"""
        self.client.close()

# Helper functions for Flask routes
def get_vt_scanner():
    """Get initialized VirusTotal scanner"""
    return VirusTotalScanner()

def scan_single_url(url, force_rescan=False):
    """Scan a single URL (for manual scanning)"""
    scanner = get_vt_scanner()
    result = scanner.scan_url(url, force_rescan=force_rescan)
    scanner.close()
    return result
    


def scan_urls(url_list):
    """Scan multiple URLs (for backward compatibility)"""
    scanner = get_vt_scanner()
    results = []
    for url in url_list:
        result = scanner.scan_url(url)
        if result:
            results.append(result)
        # Rate limiting
        if url != url_list[-1]:
            time.sleep(15)
    scanner.close()
    return results


def get_scan_history():
    """Get scan history from MongoDB"""
    return list(vt_results_collection.find().sort("last_checked", -1).limit(50))

def get_threat_level(result):
    """Determine threat level based on scan results"""
    if not result:
        return "unknown"
    
    malicious = result.get('malicious', 0)
    suspicious = result.get('suspicious', 0)
    
    if malicious >= 5:
        return "high"
    elif malicious >= 2:
        return "medium"
    elif malicious >= 1 or suspicious >= 3:
        return "low"
    else:
        return "clean"

def check_api_key_setup():
    """Check if API key is properly configured"""
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return "❌ No API key found in .env file"
    elif api_key == "your_actual_virustotal_api_key_here":
        return "❌ Still using placeholder API key in .env file"
    elif len(api_key) != 64:
        return f"❌ Invalid API key length: {len(api_key)} characters (should be 64)"
    else:
        return f"✅ API key configured (length: {len(api_key)} characters)"

# Enhanced function for rescan with force option
def rescan_url(url):
    """Force rescan of a URL (bypass cache)"""
    print(f"🔄 Force rescan requested for: {url}")
    return scan_single_url(url, force_rescan=True)