from bs4 import BeautifulSoup

class HtmlAnalyzer:
    """Semantic HTML parser and difference analyzer for tamper detection."""

    @staticmethod
    def extract_core_features(html):
        """Extract sanitized, noise-free semantic features from HTML."""
        if not html:
            return {}

        soup = BeautifulSoup(html, "html.parser")

        # Decompose dynamic and non-visual elements
        for tag in soup(["script", "style", "iframe", "noscript", "svg"]):
            tag.decompose()

        # Strip ads, carousels, and rotating banners to prevent false positives
        for div in soup.find_all(
            ["div", "section"],
            class_=lambda x: x and any(k in x.lower() for k in ["ad", "slider", "carousel", "banner"])
        ):
            div.decompose()

        core_text = soup.get_text(separator=" ", strip=True)
        core_text = " ".join(core_text.split())

        return {
            "title": soup.title.string.strip() if soup.title and soup.title.string else "",
            "h1": [h.text.strip() for h in soup.find_all("h1")],
            "h2": [h.text.strip() for h in soup.find_all("h2")],
            "text_sample": core_text[:1500],
            "text_length": len(core_text)
        }

    @staticmethod
    def has_core_changed(old_features, new_features):
        """
        Evaluate if core structural or textual HTML content has shifted.
        Preserves original TamperTrace rules:
          1. Title change
          2. H1 headings change
          3. Text length deviation > 20% (for text length > 300)
          4. Introductory 300-char core text slice change
        """
        if not old_features or not new_features:
            return False

        # 1. Page Title change (strong defacement signal)
        if old_features.get("title", "").strip() != new_features.get("title", "").strip():
            return True

        # 2. Main Headings changed
        if set(old_features.get("h1", [])) != set(new_features.get("h1", [])):
            return True

        # 3. Significant text length deviation (>20%)
        old_len = old_features.get("text_length", 0)
        new_len = new_features.get("text_length", 0)
        if old_len > 300 and abs(new_len - old_len) / old_len > 0.20:
            return True

        # 4. Core introductory text changed
        if old_features.get("text_sample", "")[:300] != new_features.get("text_sample", "")[:300]:
            return True

        return False
