import os
import hashlib
import datetime
import cv2
import numpy as np
from config import Config

class VisualAnalyzer:
    """Computer vision image difference analyzer using SSIM and OpenCV."""

    @staticmethod
    def compare_screenshots(img1_path, img2_path, upload_folder=None):
        """
        Compare two screenshots using Structural Similarity Index (SSIM) or CV2 threshold.
        Generates diff heatmap image into upload folder.
        Returns: (diff_percentage, diff_image_path, is_meaningful)
        """
        output_dir = upload_folder or Config.UPLOAD_FOLDER
        os.makedirs(output_dir, exist_ok=True)

        try:
            if not img1_path or not img2_path:
                return 0.0, "", False
            if not os.path.exists(img1_path) or not os.path.exists(img2_path):
                return 0.0, "", False

            imgA = cv2.imread(img1_path)
            imgB = cv2.imread(img2_path)
            if imgA is None or imgB is None:
                return 0.0, "", False

            # Normalize to standardized resolution for comparison
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
            diff_path = os.path.join(output_dir, diff_filename)

            if len(diff_img.shape) == 2:
                cv2.imwrite(diff_path, diff_img)
            else:
                cv2.imwrite(diff_path, cv2.cvtColor(diff_img, cv2.COLOR_BGR2RGB))

            return diff_percentage, diff_path, is_meaningful

        except Exception as e:
            print(f"❌ Screenshot comparison failed: {e}")
            return 0.0, "", False
