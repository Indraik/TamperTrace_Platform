import re
from urllib.parse import urlparse

class Validators:
    """Input validation utilities."""

    @staticmethod
    def is_valid_url(url):
        """Validate URL schema and network location."""
        if not url or not isinstance(url, str):
            return False
        try:
            parsed = urlparse(url.strip())
            return bool(parsed.scheme in ("http", "https") and parsed.netloc)
        except Exception:
            return False

    @staticmethod
    def is_valid_email(email):
        """Validate basic email format."""
        if not email or not isinstance(email, str):
            return False
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        return bool(re.match(pattern, email.strip()))
