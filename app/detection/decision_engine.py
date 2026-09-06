from config import Config
from app.detection.html_analyzer import HtmlAnalyzer

class DecisionEngine:
    """Evaluates semantic and visual difference outputs to classify events as TAMPER or IGNORE."""

    @staticmethod
    def evaluate(old_core, new_core, diff_percent, threshold=None):
        """
        Decision criteria (strictly preserving original TamperTrace logic):
          1. If core HTML content changed -> TAMPER
          2. Else if visual diff exceeds threshold AND core text sample changed -> TAMPER
          3. Else -> IGNORE (dynamic content/ads/sliders/banners)

        Returns:
            (decision, reason) -> tuple of ('TAMPER'|'IGNORE', explanation string)
        """
        diff_threshold = threshold if threshold is not None else Config.VISUAL_DIFF_THRESHOLD

        html_changed = HtmlAnalyzer.has_core_changed(old_core, new_core)
        core_text_changed = old_core.get("text_sample", "") != new_core.get("text_sample", "")
        visual_changed = diff_percent > diff_threshold

        if html_changed:
            return "TAMPER", "Core HTML content changed"
        elif visual_changed and core_text_changed:
            return "TAMPER", "Visual + core text change detected"
        else:
            return "IGNORE", "Dynamic content / ads / sliders"
