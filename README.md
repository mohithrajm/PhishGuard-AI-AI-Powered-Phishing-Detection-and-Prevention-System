# PhishGuard AI: AI-Powered Phishing Detection and Prevention System

An end-to-end multi-vector cybersecurity platform utilizing Machine Learning, Natural Language Processing (NLP), and automated mitigation playbooks to detect and neutralize phishing attacks across URLs, domains, and email communications in real time.

---

## Key Features

### 1. Multi-Vector Threat Intelligence Engine
- **URL & Domain Lexical Extractor**: Analyzes 28+ lexical, statistical (Shannon entropy), and structural signals including deep subdomains, port presence, digit ratios, and character distributions.
- **Brand Impersonation & Typosquatting Engine**: Detects adversarial homoglyphs, Punycode (IDN), and tokenized Levenshtein edit distance targeting major enterprise and financial brands (PayPal, Microsoft, Apple, Amazon, Chase, etc.).
- **Email NLP & Social Engineering Analyzer**: Identifies psychological coercion, manufactured urgency (e.g. "within 24 hours", "account suspended"), deceptive call-to-actions, and mismatched hyperlinks.
- **Sender Header Discrepancy Validator**: Flags display-name spoofing and free webmail abuse impersonating corporate security teams.

### 2. Machine Learning Core (Strict Google Antigravity ML Best Practices)
- **Zero Data Leakage**: 70% Train, 15% Validation, and 15% Test partitioning strictly executed *before* fitting scalers and vectorizers.
- **Multi-Model Benchmarking**: Benchmarks Naive Majority Baseline, Logistic Regression, Random Forest Classifier, and Gradient Boosting.
- **Statistical Rigor**: 95% Bootstrap Confidence Intervals computed across 1,000 resamples for key test metrics.
- **Slice-Based Error Analysis**: Evaluates performance across critical attack slices (IP address hosts, typosquatted brands, suspicious TLDs, and high-entropy DGA domains).
- **Explainable AI (XAI)**: Gini feature importance attribution providing human-readable explanations for security operations center (SOC) analysts.

### 3. Automated Prevention & Defense Center
- **Dynamic DNS Sinkholing & Blocklist Export**: One-click generation and live download of firewall blocklists in:
  - Windows/Linux `hosts` file format (`0.0.0.0 evil.com`)
  - DNS Response Policy Zone (`RPZ`) format for BIND/Unbound
  - AdGuard Home / Pi-hole filter list syntax (`||evil.com^`)
- **Safe URL Defanging**: Automatically neutralizes malicious URLs (`hxxps[://]evil[.]com`) for safe incident ticketing.
- **Email Quarantine & In-Transit Security Banners**: Generates safe sandboxed warning banners for mail transfer agents (MTAs).

### 4. Interactive Cyber Intelligence Console & REST API
- **Live Dark-Mode Dashboard**: Real-time gauge metrics, instant attack presets, threat radar, and visual explainability charts.
- **FastAPI Backend**: Clean, typed RESTful endpoints for enterprise integration.

---

## Repository Structure

```
phishing_detection_system/
├── data/
│   ├── urls_dataset.csv          # Generated balanced dataset (4,000 samples)
│   ├── emails_dataset.csv        # Generated balanced email corpus (1,200 samples)
│   ├── blocked_domains.json      # Dynamic active firewall sinkhole database
│   └── quarantine_log.json       # Incident audit records
├── models/
│   ├── url_model.joblib          # Trained Random Forest URL model & scaler
│   ├── email_model.joblib        # Trained Email NLP model & TF-IDF vectorizer
│   ├── metrics.json              # Full evaluation telemetry and comparison results
│   └── model_evaluation_report.md# Formal ML evaluation report with 95% CI
├── src/
│   ├── ml/
│   │   ├── url_feature_extractor.py # 28+ URL lexical & typosquatting features
│   │   ├── email_nlp_extractor.py   # Urgency, coercion, and spoofing analyzer
│   │   ├── dataset_generator.py     # Benchmark dataset generation
│   │   └── train_models.py          # ML training and benchmarking pipeline
│   ├── defense/
│   │   └── prevention_engine.py     # Blocklist exporter, defanger, quarantine
│   ├── api/
│   │   └── main.py                  # FastAPI server and REST endpoints
│   └── web/
│       └── templates/
│           └── index.html           # Modern Cyber Threat Intelligence Dashboard
├── tests/
│   └── test_system.py               # Unit & integration test suite (17 tests)
├── requirements.txt                 # Pinned dependencies
├── run_server.py                    # Server launcher
└── README.md                        # Documentation
```

---

## Quickstart Guide

### 1. Setup Virtual Environment & Install Dependencies
```bash
python -m venv .venv

# On Windows:
.\.venv\Scripts\activate
pip install -r requirements.txt

# On Linux/macOS:
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Generate Datasets & Train Models
```bash
# Generate benchmark datasets
python src/ml/dataset_generator.py

# Train and compare models (evaluated on test split)
python src/ml/train_models.py
```

### 3. Run Automated Test Suite
```bash
pytest tests/test_system.py -v
```

### 4. Launch the Web Console & REST API
```bash
python run_server.py
```
Open your browser at:
- **Interactive Web Console**: `http://127.0.0.1:8000`
- **Interactive Swagger API Docs**: `http://127.0.0.1:8000/docs`

---

## API Reference

### `POST /api/scan/url`
Scans a target URL or domain, runs feature extraction and Random Forest inference, and triggers automated defense actions if malicious.

**Request:**
```json
{
  "url": "http://paypa1-security-verification.xyz/login?session_id=89412"
}
```

**Response:**
```json
{
  "url": "http://paypa1-security-verification.xyz/login?session_id=89412",
  "defanged_url": "hxxp[://]paypa1-security-verification[.]xyz/login?session_id=89412",
  "risk_score": 100.0,
  "verdict": "MALICIOUS",
  "recommended_action": "BLOCK_AND_SINKHOLE",
  "ml_phishing_probability": 1.0,
  "risk_indicators": [
    "Potential typosquatting/brand impersonation detected targeting 'paypal'.",
    "Top-Level Domain (.xyz) has a high historical abuse rate.",
    "Contains multiple sensitive keywords: login, security.",
    "Insecure HTTP protocol used on a credential/sensitive page."
  ]
}
```

### `POST /api/scan/email`
Scans inbound email headers, body text, and embedded hyperlinks.

**Request:**
```json
{
  "subject": "URGENT: Your account has been suspended due to unauthorized activity!",
  "sender": "PayPal Security Support <service-notice@account-verify-sec.xyz>",
  "body": "Click here immediately: http://paypal-verify-account.xyz/login"
}
```

### `GET /api/prevention/blocklist?format={hosts|rpz|adguard|plain}`
Exports live firewall and DNS blocklists.

### `GET /api/telemetry/stats`
Returns system telemetry, counters, and loaded model metadata.

### `POST /api/simulate`
Returns pre-packaged attack scenarios for cybersecurity training drills.