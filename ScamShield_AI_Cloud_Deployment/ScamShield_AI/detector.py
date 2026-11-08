"""ScamShield's demo detector: classical text model + transparent signals + optional Qiskit VQC."""
import re
from urllib.parse import urlparse

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from quantum_classifier import QuantumScamClassifier

# Small illustrative examples only. Replace with a licensed, representative, labelled dataset
# before using this for serious evaluation or real-world decisions.
TRAINING_DATA = [
    ("Your parcel is delayed. Track your shipment in the official app.", 0),
    ("Your bank statement is ready. Sign in through the bank's official app.", 0),
    ("The meeting is scheduled for 3 PM. Please review the attached agenda.", 0),
    ("Your appointment reminder is for tomorrow at 10 AM.", 0),
    ("Thanks for your order. You can view the receipt in your account.", 0),
    ("Please call me when you have time to discuss the project.", 0),
    ("URGENT: Your account will be blocked. Verify your password immediately at http://secure-login-example.invalid", 1),
    ("Congratulations you won a prize. Pay a processing fee now to claim it.", 1),
    ("Your bank account is suspended. Send your OTP to restore access.", 1),
    ("You have an unpaid fine. Pay immediately using this unusual link.", 1),
    ("Work from home and earn guaranteed money. Pay a registration fee first.", 1),
    ("Your KYC expires today. Click here and enter your card PIN to avoid closure.", 1),
    ("We detected suspicious activity. Reply with your one-time password.", 1),
    ("Investment guaranteed to double your money in two days. Act now.", 1),
    ("Your package is held. Pay a small redelivery fee through this link.", 1),
    ("I am a support agent. Share your remote access code so I can fix your account.", 1),
]

SUSPICIOUS_PHRASES = {
    "urgent": "Uses urgency or pressure",
    "act now": "Pressures you to act immediately",
    "verify your password": "Requests password verification through a message",
    "send your otp": "Requests a one-time password (OTP)",
    "share your otp": "Requests a one-time password (OTP)",
    "card pin": "Mentions a card PIN request",
    "processing fee": "Requests an upfront fee to claim a reward",
    "guaranteed to double": "Promises unusually guaranteed returns",
    "pay immediately": "Pressures you to make an immediate payment",
    "account will be blocked": "Threatens account closure",
    "suspended": "Uses an account-suspension threat",
    "remote access": "Requests remote access or control",
    "registration fee": "Requests an upfront job fee",
    "click here": "Encourages clicking a link without context",
    "kyc expires": "Uses a KYC-expiry warning to create urgency",
}

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)


class ScamDetector:
    def __init__(self):
        self.model = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True, max_features=4000)),
            ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)),
        ])
        self.model.fit([x for x, _ in TRAINING_DATA], [y for _, y in TRAINING_DATA])
        self.quantum = QuantumScamClassifier()

    @staticmethod
    def classify(score):
        """Map a 0-100 risk score to (label, level)."""
        if score >= 65:
            return "Potential scam", "High"
        if score >= 35:
            return "Suspicious — verify independently", "Medium"
        return "No strong scam signals detected", "Low"

    def retrain(self, extra=None):
        """Refit the classical model on the bundled examples plus extra (text, label) pairs."""
        data = TRAINING_DATA + [(t, int(y)) for t, y in (extra or []) if t]
        self.model.fit([x for x, _ in data], [y for _, y in data])
        return len(data)

    @staticmethod
    def _inspect_urls(text):
        found = URL_RE.findall(text)
        output, warnings = [], []
        for raw in found:
            cleaned = raw.rstrip(".,);]!?}")
            candidate = cleaned if cleaned.lower().startswith(("http://", "https://")) else "http://" + cleaned
            parsed = urlparse(candidate)
            host = (parsed.hostname or "").lower()
            notes = []
            if parsed.scheme == "http":
                notes.append("Uses HTTP rather than HTTPS")
            if host and (host.replace(".", "").isdigit() or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)):
                notes.append("Uses an IP address instead of a familiar domain")
            if host.startswith("xn--") or ".xn--" in host:
                notes.append("Contains an internationalized domain name that may need extra scrutiny")
            if len(host) > 45:
                notes.append("Has an unusually long hostname")
            if host.count("-") >= 3:
                notes.append("Hostname contains several hyphens")
            if any(word in host for word in ("login", "verify", "secure", "account", "update")):
                notes.append("Hostname uses a security-related word; verify the domain independently")
            output.append({"url": cleaned, "host": host, "notes": notes})
            warnings.extend(notes)
        return output, warnings

    def analyze(self, text):
        cleaned = text.strip()
        signals = []
        lower = cleaned.lower()
        for phrase, explanation in SUSPICIOUS_PHRASES.items():
            if phrase in lower:
                signals.append(explanation)
        urls, url_warnings = self._inspect_urls(cleaned)
        signals.extend(url_warnings)

        classical_probability = float(self.model.predict_proba([cleaned])[0][1])
        # Transparent heuristics are deliberately capped so they cannot alone prove fraud.
        heuristic_score = min(0.95, 0.12 * len(set(signals)))
        classical_score = 100 * classical_probability
        combined = 0.78 * classical_score + 0.22 * (100 * heuristic_score)

        quantum_probability = None
        quantum_note = "Quantum component unavailable; classical model used."
        if self.quantum.available:
            try:
                quantum_probability = self.quantum.predict_proba(self._quantum_features(cleaned, signals, urls))
                combined = 0.70 * classical_score + 0.20 * (100 * heuristic_score) + 0.10 * (100 * quantum_probability)
                quantum_note = "Experimental Qiskit circuit score included (low weight; demo model)."
            except Exception as exc:  # keep app available if quantum dependencies/simulator fail
                quantum_note = f"Quantum component could not run; classical model used ({type(exc).__name__})."

        score = int(round(max(0, min(100, combined))))
        label, level = self.classify(score)

        if not signals:
            signals.append("No listed warning phrase was detected; this does not guarantee the message is safe.")
        advice = [
            "Do not share passwords, OTPs, card PINs, or recovery codes with anyone.",
            "Do not pay an unexpected fee or open a link just because a message creates urgency.",
            "Contact the organization using its official app, website typed manually, or a known phone number.",
        ]
        if urls:
            advice.insert(0, "Avoid opening the detected link until you independently verify the domain.")
        return {
            "label": label, "risk": score, "level": level,
            "explanation": "This is a screening estimate, not proof. Scams can look legitimate and legitimate messages can look unusual.",
            "signals": signals, "urls": urls, "advice": advice,
            "models": {"classical_probability": round(classical_probability, 3),
                       "quantum_probability": None if quantum_probability is None else round(quantum_probability, 3),
                       "quantum_note": quantum_note},
        }

    @staticmethod
    def _quantum_features(text, signals, urls):
        lower = text.lower()
        features = [
            min(len(text) / 500.0, 1.0),
            min(len(URL_RE.findall(text)) / 3.0, 1.0),
            min(len(signals) / 8.0, 1.0),
            float(any(w in lower for w in ("urgent", "immediately", "act now", "today"))),
        ]
        return np.asarray(features, dtype=float)
