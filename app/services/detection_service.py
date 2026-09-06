import os
import hashlib
import datetime
import cv2
import numpy as np
from bs4 import BeautifulSoup
from config import Config

class DetectionService:
    """Service handling HTML semantic parsing, visual diffing, and tamper decisions."""

    @staticmethod
    def extract_core_html_features(html):
        """Extract sanitized, noise-free semantic features from HTML."""
        if not html:
            return {}

        soup = BeautifulSoup(html, "html.parser")

        # Decompose dynamic and non-visual elements
        for tag in soup(["script", "style", "iframe", "noscript", "svg"]):
            tag.decompose()

        # Strip ads, carousels, and rotating banners
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
    def core_html_changed(old, new):
        """Evaluate if core structural or textual HTML content has shifted."""
        if not old or not new:
            return False

        # 1. Page Title change (strong defacement signal)
        if old.get("title", "").strip() != new.get("title", "").strip():
            return True

        # 2. Main Headings changed
        if set(old.get("h1", [])) != set(new.get("h1", [])):
            return True

        # 3. Significant text length deviation (>20%)
        old_len = old.get("text_length", 0)
        new_len = new.get("text_length", 0)
        if old_len > 300 and abs(new_len - old_len) / old_len > 0.20:
            return True

        # 4. Core introductory text changed
        if old.get("text_sample", "")[:300] != new.get("text_sample", "")[:300]:
            return True

        return False

    @staticmethod
    def compare_screenshots_meaningful(img1_path, img2_path):
        """
        Compare screenshots using SSIM (Structural Similarity Index) or CV2 threshold.
        Returns: (diff_percentage, diff_image_path, is_meaningful)
        """
        try:
            if not img1_path or not img2_path:
                return 0.0, "", False
            if not os.path.exists(img1_path) or not os.path.exists(img2_path):
                return 0.0, "", False

            imgA = cv2.imread(img1_path)
            imgB = cv2.imread(img2_path)
            if imgA is None or imgB is None:
                return 0.0, "", False

            # Resize to normalized resolution for comparison
            w, h = 800, 600
            imgA = cv2.resize(imgA, (w, h))
            imgB = cv2.resize(imgB, (w, h))

            grayA = cv2.cvtColor(imgA, cv2.COLOR_BGR2GRAY)
            grayB = cv2.cvtColor(imgB, cv2.COLOR_BGR2GRAY)

            try:
                from skimage.metrics import structural_similarity as ssim
                score, diff = ssim(grayA, grayB, full=True)
                diff_img = ((1 - diff) * 255).astype("uint8")
                diff_percentage = (1 - score) * 100
                is_meaningful = score < 0.85
            except Exception:
                diff_raw = cv2.absdiff(grayA, grayB)
                _, thresh = cv2.threshold(diff_raw, 30, 255, cv2.THRESH_BINARY)
                non_zero = cv2.countNonZero(thresh)
                total = thresh.shape[0] * thresh.shape[1]
                diff_percentage = (non_zero / total) * 100
                diff_img = thresh
                is_meaningful = diff_percentage > 15
                score = 1 - (diff_percentage / 100)

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            diff_filename = f"diff_{timestamp}_{hashlib.md5((img1_path + img2_path).encode()).hexdigest()[:8]}.png"
            diff_path = os.path.join(Config.UPLOAD_FOLDER, diff_filename)

            if len(diff_img.shape) == 2:
                cv2.imwrite(diff_path, diff_img)
            else:
                cv2.imwrite(diff_path, cv2.cvtColor(diff_img, cv2.COLOR_BGR2RGB))

            return diff_percentage, diff_path, is_meaningful

        except Exception as e:
            print(f"❌ Screenshot comparison failed: {e}")
            return 0.0, "", False

    @classmethod
    def decide_tamper(cls, old_core, new_core, diff_percent):
        """
        Evaluate dual-layer criteria to separate real defacements from dynamic noise.
        Returns: (decision, reason)
        """
        html_changed = cls.core_html_changed(old_core, new_core)
        core_text_changed = old_core.get("text_sample", "") != new_core.get("text_sample", "")
        visual_changed = diff_percent > Config.VISUAL_DIFF_THRESHOLD

        if html_changed:
            return "TAMPER", "Core HTML content changed"
        elif visual_changed and core_text_changed:
            return "TAMPER", "Visual + core text change detected"
        else:
            return "IGNORE", "Dynamic content / ads / sliders"
