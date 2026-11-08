# ScamShield AI architecture

1. **Input:** user pastes message, email text, or URL in the Flask web interface.
2. **Preprocessing:** text is normalized by TF-IDF; simple URL parsing and transparent warning-signal rules inspect the input.
3. **Classical ML:** a scikit-learn TF-IDF + logistic-regression pipeline returns a demo scam probability.
4. **Experimental quantum component:** four normalized features are encoded into a four-qubit Qiskit circuit, followed by entangling gates and parameterized rotations. A statevector simulator estimates Pauli-Z expectations and maps them to an experimental score.
5. **Fusion and explanation:** the app combines model scores with a capped heuristic score, lists observed signals, and gives safety advice.
6. **Output:** risk estimate, level, warning signs, detected URLs, model diagnostics, and recommended precautions.

## Backend layer (added)

- **Flask app factory** with blueprints: `web` (pages), `auth`, `api` (JSON, key-authenticated), `admin`.
- **SQLAlchemy models** (users, scans, reports, blocked_domains) on SQLite or PostgreSQL.
- **services.py** wraps the detector: runs the analysis, applies the community blocklist (raises risk to at least 85), stores the scan, and handles reports, retraining and statistics.
- **Learning loop**: confirmed reports and user verdicts become extra labelled examples when the classifier is retrained.
- **Security**: hashed passwords, CSRF tokens, API keys, rate limiting, security headers, owner-only access to scans.

## Limitations

The bundled training examples are tiny and illustrative, not a representative dataset. Quantum parameters are illustrative and are not trained; the quantum output is a demonstration of circuit integration, not evidence of a useful quantum advantage. Do not claim improved accuracy without a proper train/test split, repeated evaluation, and comparison against a classical baseline. URL rules are heuristic and cannot establish whether a site is malicious.
