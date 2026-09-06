"""
DetectionService - Facade delegating to specialized detection modules
(HtmlAnalyzer, VisualAnalyzer, DecisionEngine in app.detection)
"""
from app.detection.html_analyzer import HtmlAnalyzer
from app.detection.visual_analyzer import VisualAnalyzer
from app.detection.decision_engine import DecisionEngine

class DetectionService:
    """Service facade for semantic HTML parsing, visual diffing, and tamper decisions."""

    @staticmethod
    def extract_core_html_features(html):
        return HtmlAnalyzer.extract_core_features(html)

    @staticmethod
    def core_html_changed(old, new):
        return HtmlAnalyzer.has_core_changed(old, new)

    @staticmethod
    def compare_screenshots_meaningful(img1_path, img2_path):
        return VisualAnalyzer.compare_screenshots(img1_path, img2_path)

    @classmethod
    def decide_tamper(cls, old_core, new_core, diff_percent):
        return DecisionEngine.evaluate(old_core, new_core, diff_percent)
