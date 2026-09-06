import unittest
from app.detection.html_analyzer import HtmlAnalyzer
from app.detection.decision_engine import DecisionEngine

class TestDetection(unittest.TestCase):
    """Unit tests for semantic HTML analysis and decision engine."""

    def test_extract_core_features(self):
        html = """
        <html>
            <head><title>Test Secure Portal</title></head>
            <body>
                <script>alert('dynamic tracking');</script>
                <div class="ad-banner">Ad 50% Off</div>
                <div class="slider-item">Slider Image 1</div>
                <h1>Main Heading</h1>
                <h2>Sub Heading</h2>
                <p>This is legitimate clean web content for testing purposes.</p>
            </body>
        </html>
        """
        features = HtmlAnalyzer.extract_core_features(html)
        self.assertEqual(features["title"], "Test Secure Portal")
        self.assertEqual(features["h1"], ["Main Heading"])
        self.assertEqual(features["h2"], ["Sub Heading"])
        self.assertIn("legitimate clean web content", features["text_sample"])
        # Ensure ads and scripts were stripped
        self.assertNotIn("Ad 50% Off", features["text_sample"])
        self.assertNotIn("dynamic tracking", features["text_sample"])

    def test_has_core_changed_title(self):
        old = {"title": "Official Portal", "h1": ["Home"], "text_sample": "Welcome", "text_length": 100}
        new = {"title": "Hacked by 1337", "h1": ["Home"], "text_sample": "Welcome", "text_length": 100}
        self.assertTrue(HtmlAnalyzer.has_core_changed(old, new))

    def test_has_core_changed_headings(self):
        old = {"title": "Portal", "h1": ["Welcome"], "text_sample": "Text", "text_length": 50}
        new = {"title": "Portal", "h1": ["Defaced Message"], "text_sample": "Text", "text_length": 50}
        self.assertTrue(HtmlAnalyzer.has_core_changed(old, new))

    def test_decision_engine_tamper_on_html_change(self):
        old = {"title": "Safe", "h1": ["Hello"], "text_sample": "Legitimate content", "text_length": 100}
        new = {"title": "Pwned", "h1": ["Hello"], "text_sample": "Legitimate content", "text_length": 100}
        decision, reason = DecisionEngine.evaluate(old, new, diff_percent=2.0)
        self.assertEqual(decision, "TAMPER")
        self.assertIn("Core HTML content changed", reason)

    def test_decision_engine_ignore_on_visual_only_diff(self):
        # When text is identical and only an ad/carousel shifted (visual diff > 8% but core text unchanged)
        old = {"title": "Safe", "h1": ["Hello"], "text_sample": "Same content", "text_length": 100}
        new = {"title": "Safe", "h1": ["Hello"], "text_sample": "Same content", "text_length": 100}
        decision, reason = DecisionEngine.evaluate(old, new, diff_percent=15.0)
        self.assertEqual(decision, "IGNORE")
        self.assertIn("Dynamic content / ads / sliders", reason)

    def test_decision_engine_tamper_on_visual_plus_text_diff(self):
        # Change is beyond first 300 chars so has_core_changed is False, but full text_sample is different
        prefix = "A" * 350
        old = {"title": "Safe", "h1": ["Hello"], "text_sample": prefix + " OLD TEXT", "text_length": 400}
        new = {"title": "Safe", "h1": ["Hello"], "text_sample": prefix + " NEW TEXT", "text_length": 400}
        decision, reason = DecisionEngine.evaluate(old, new, diff_percent=12.0)
        self.assertEqual(decision, "TAMPER")
        self.assertIn("Visual + core text change detected", reason)

if __name__ == "__main__":
    unittest.main()
