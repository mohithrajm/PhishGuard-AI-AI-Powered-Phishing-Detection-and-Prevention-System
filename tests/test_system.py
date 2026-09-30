# Comprehensive Test Suite for AI Phishing Detection & Prevention System
import os
import sys
import pytest
from fastapi.testclient import TestClient

# Ensure src modules are discoverable
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(project_root, "src", "ml"))
sys.path.insert(0, os.path.join(project_root, "src", "defense"))
sys.path.insert(0, os.path.join(project_root, "src", "api"))

from url_feature_extractor import extract_url_features, shannon_entropy, levenshtein_distance
from email_nlp_extractor import extract_email_features
from prevention_engine import PreventionEngine
from main import app

# 1. Feature Extraction Tests
def test_levenshtein_distance():
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypa1", "paypal") == 1
    assert levenshtein_distance("amaz0n", "amazon") == 1
    assert levenshtein_distance("google", "microsoft") > 4

def test_shannon_entropy():
    # Uniform string has low entropy
    low_ent = shannon_entropy("aaaaaaa")
    assert low_ent == 0.0
    # High randomness has higher entropy
    high_ent = shannon_entropy("a8f93e2b71c9")
    assert high_ent > 3.0

def test_url_features_typosquat():
    res = extract_url_features("http://paypa1-security.com/login")
    f = res["features"]
    assert f["is_brand_spoofed"] == 1
    assert res["meta"]["target_brand"] == "paypal"
    assert f["has_suspicious_keyword"] == 1
    assert any("typosquatting" in ind.lower() for ind in res["indicators"])

def test_url_features_raw_ip():
    res = extract_url_features("http://192.168.1.100:8080/account/verify")
    f = res["features"]
    assert f["is_ip"] == 1
    assert f["has_port"] == 0  # port is part of netloc but raw IP flag is prioritized
    assert any("raw IP address" in ind for ind in res["indicators"])

def test_url_features_legitimate_brand():
    res = extract_url_features("https://www.paypal.com/signin")
    f = res["features"]
    # Authentic domain should NOT be marked as brand spoofed
    assert f["is_brand_spoofed"] == 0

def test_url_features_suspicious_tld():
    res = extract_url_features("http://mybank-portal.xyz/login")
    assert res["features"]["is_suspicious_tld"] == 1

# 2. Email NLP & Behavioral Tests
def test_email_urgency_and_spoofing():
    subject = "URGENT: Your PayPal account has been suspended within 24 hours"
    sender = "PayPal Team <service@fake-domain.xyz>"
    body = "Click here immediately to restore access: http://fake-paypal.xyz/login"
    
    res = extract_email_features(subject, body, sender)
    assert res["features"]["urgency_score"] >= 2
    assert res["features"]["num_links"] == 1
    assert res["sender_analysis"]["is_spoofed"] == 1
    assert any("urgency" in ind.lower() for ind in res["indicators"])

def test_email_legitimate_newsletter():
    subject = "Weekly developer community update"
    sender = "Tech Newsletter <newsletter@developer-news.org>"
    body = "Here are the top open source tools this week for building python apps."
    
    res = extract_email_features(subject, body, sender)
    assert res["features"]["urgency_score"] == 0
    assert res["sender_analysis"]["is_spoofed"] == 0

# 3. Prevention Engine Tests
def test_url_defanging():
    eng = PreventionEngine(blocklist_file="data/test_blocklist.json", quarantine_file="data/test_quarantine.json")
    assert eng.defang_url("https://malicious.com/path") == "hxxps[://]malicious[.]com/path"
    assert eng.defang_url("http://192.168.1.1/login") == "hxxp[://]192[.]168[.]1[.]1/login"

def test_blocklist_generation():
    eng = PreventionEngine(blocklist_file="data/test_blocklist.json", quarantine_file="data/test_quarantine.json")
    eng.blocked_domains.add("evil-phish.xyz")
    eng.blocked_domains.add("bank-fraud.top")
    
    hosts_txt = eng.export_blocklist("hosts")
    assert "0.0.0.0 evil-phish.xyz" in hosts_txt
    assert "0.0.0.0 bank-fraud.top" in hosts_txt

    rpz_txt = eng.export_blocklist("rpz")
    assert "evil-phish.xyz CNAME ." in rpz_txt

    adguard_txt = eng.export_blocklist("adguard")
    assert "||evil-phish.xyz^" in adguard_txt

    # Clean up test files if generated
    if os.path.exists("data/test_blocklist.json"):
        os.remove("data/test_blocklist.json")
    if os.path.exists("data/test_quarantine.json"):
        os.remove("data/test_quarantine.json")

# 4. End-to-End API Integration Tests
client = TestClient(app)

def test_api_scan_malicious_url():
    resp = client.post("/api/scan/url", json={"url": "http://paypa1-verify-account.xyz/login?urgent=true"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] in ["MALICIOUS", "SUSPICIOUS"]
    assert data["risk_score"] >= 70
    assert data["recommended_action"] in ["BLOCK_AND_SINKHOLE", "WARN_USER"]
    assert "defanged_url" in data

def test_api_scan_legitimate_url():
    resp = client.post("/api/scan/url", json={"url": "https://github.com/scikit-learn/scikit-learn"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "SAFE"
    assert data["risk_score"] < 35
    assert data["recommended_action"] == "ALLOW"

def test_api_scan_phishing_email():
    payload = {
        "subject": "CRITICAL ALERT: Your Microsoft 365 account expires in 2 hours",
        "sender": "Microsoft IT Helpdesk <admin-support@outlook-service-alert.top>",
        "body": "ACTION REQUIRED: A critical security vulnerability was identified. Log in immediately: http://login-microsoft365-portal.top/auth"
    }
    resp = client.post("/api/scan/email", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] in ["PHISHING_MALICIOUS", "SUSPICIOUS_EMAIL"]
    assert data["risk_score"] >= 70
    assert len(data["scanned_links"]) >= 1

def test_api_metrics_endpoint():
    resp = client.get("/api/models/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "urls" in data
    assert "emails" in data
    assert "comparison" in data["urls"]

def test_api_telemetry_endpoint():
    resp = client.get("/api/telemetry/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "counters" in data
    assert "blocked_domains_count" in data

def test_api_blocklist_export():
    resp = client.get("/api/prevention/blocklist?format=hosts")
    assert resp.status_code == 200
    assert "0.0.0.0" in resp.text

def test_api_simulation_vectors():
    resp = client.post("/api/simulate")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["scenarios"]) >= 4