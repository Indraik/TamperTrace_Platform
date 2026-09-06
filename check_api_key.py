import os
from dotenv import load_dotenv


load_dotenv()


def check_api_key():
    """Check VirusTotal API key status from environment."""
    
    api_key = os.getenv("VT_API_KEY", "").strip()
    
    print("🔑 Checking VirusTotal API key...")
    print("=" * 50)
    
    # Basic validation
    if not api_key:
        print("❌ ERROR: VT_API_KEY is not set in environment/.env")
        return False
    
    if len(api_key) == 64:
        print("✅ Format: Valid 64-character API key")
    else:
        print(f"⚠️  Format: Unusual length ({len(api_key)} characters)")
    
    # Show key preview (security: don't show full key)
    print(f"📝 Key preview: {api_key[:6]}...{api_key[-6:]}")
    
    # Test the key by trying to import and use it
    try:
        import vt
        client = vt.Client(api_key)
        # Try to get current user info (lightweight test)
        user_info = client.get_object("/users/current")
        client.close()
        
        print("✅ Status: API key is ACTIVE and working")
        print(f"👤 Account: {user_info.data.attributes.email}")
        print("🎯 Privileges: Standard API (4 req/min, 500 req/day)")
        return True
        
    except Exception as e:
        print(f"❌ Status: API key validation failed")
        print(f"💡 Error: {e}")
        return False

if __name__ == "__main__":
    check_api_key()