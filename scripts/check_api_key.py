import os
import sys

# Auto-locate project virtual environment site-packages
_base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_site_pkgs = os.path.join(_base_dir, "venv", "Lib", "site-packages")
if os.path.exists(_site_pkgs) and _site_pkgs not in sys.path:
    sys.path.insert(0, _site_pkgs)

from dotenv import load_dotenv

load_dotenv()

def check_api_key():
    """Check VirusTotal API key status from environment."""
    api_key = os.getenv("VT_API_KEY", "").strip()
    
    print("🔑 Checking VirusTotal API key...")
    print("=" * 50)
    
    if not api_key:
        print("❌ ERROR: VT_API_KEY is not set in environment/.env")
        return False
    
    if len(api_key) == 64:
        print("✅ Format: Valid 64-character API key")
    else:
        print(f"⚠️  Format: Unusual length ({len(api_key)} characters)")
    
    print(f"📝 Key preview: {api_key[:6]}...{api_key[-6:]}")
    
    try:
        import vt
        client = vt.Client(api_key)
        user_info = client.get_object("/users/current")
        client.close()
        
        print("✅ Status: API key is ACTIVE and working")
        print(f"👤 Account: {user_info.data.attributes.email}")
        print("🎯 Privileges: Standard API (4 req/min, 500 req/day)")
        return True
        
    except Exception as e:
        print("❌ Status: API key validation failed")
        print(f"💡 Error: {e}")
        return False

if __name__ == "__main__":
    check_api_key()
