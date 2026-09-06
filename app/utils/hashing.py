import hashlib

class HashingUtil:
    """Cryptographic hashing utilities."""

    @staticmethod
    def sha256_text(text):
        """Compute SHA-256 hexadecimal digest for string content."""
        if not text:
            return ""
        try:
            return hashlib.sha256(text.encode("utf-8")).hexdigest()
        except Exception:
            return hashlib.sha256(text.encode("latin-1", errors="ignore")).hexdigest()

    @staticmethod
    def sha256_file(filepath):
        """Compute SHA-256 hexadecimal digest for binary file."""
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def md5_hash(text):
        """Generate MD5 hash string (used for deterministic screenshot filenames)."""
        return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()
