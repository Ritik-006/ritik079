import unittest
from detector import ScamDetector


class DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = ScamDetector()

    def test_returns_expected_fields(self):
        result = self.detector.analyze("Please call me about tomorrow's meeting.")
        for key in ("label", "risk", "level", "signals", "urls", "advice", "models"):
            self.assertIn(key, result)
        self.assertGreaterEqual(result["risk"], 0)
        self.assertLessEqual(result["risk"], 100)

    def test_flags_otp_request(self):
        result = self.detector.analyze("Urgent: send your OTP to restore your account")
        self.assertTrue(any("OTP" in signal or "urgency" in signal.lower() for signal in result["signals"]))

    def test_detects_url(self):
        result = self.detector.analyze("Check this http://example.invalid/login")
        self.assertTrue(result["urls"])


if __name__ == "__main__":
    unittest.main()
