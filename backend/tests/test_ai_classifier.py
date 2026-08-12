import unittest

from ai_classifier import classify_by_vt_score, classify_by_vt_score_with_ai


class AiClassifierTests(unittest.TestCase):
    def test_classify_by_vt_score_true_positive(self):
        result = classify_by_vt_score(
            hash_value="abc123",
            file_path="C:/Temp/test.exe",
            vt_malicious=10,
            vt_total=20,
            vt_verdict="malicious",
        )
        self.assertEqual(result["status"], "true_positive")
        self.assertGreaterEqual(result["confidence"], 60)

    def test_classify_by_vt_score_with_ai_falls_back_cleanly(self):
        result = classify_by_vt_score_with_ai(
            hash_value="abc123",
            file_path="C:/Windows/System32/test.dll",
            vt_malicious=0,
            vt_total=10,
            vt_verdict="clean",
        )
        self.assertIn(result["status"], {"clean", "likely_false_positive", "suspicious_review"})
        self.assertIn("explanation", result)


if __name__ == "__main__":
    unittest.main()
