# FastAPI Backend for AI-Powered Phishing Detection and Prevention System
import os
import sys
import json
import joblib
import numpy as np
from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from typing import Optional, List

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
sys.path.insert(0, os.path.join(project_root, "src", "ml"))
sys.path.insert(0, os.path.join(project_root, "src", "defense"))

from url_feature_extractor import extract_url_features, FEATURE_NAMES
from email_nlp_extractor import extract_email_features
from prevention_engine import PreventionEngine

app = FastAPI(
    title="AI Phishing Detection & Prevention System",
    description="Multi-vector cyber threat intelligence and automated mitigation engine.",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

prevention = PreventionEngine(
    blocklist_file=os.path.join(project_root, "data", "blocked_domains.json"),
    quarantine_file=os.path.join(project_root, "data", "quarantine_log.json")
)

url_model_data = None
email_model_data = None
metrics_data = {}

try:
    url_model_path = os.path.join(project_root, "models", "url_model.joblib")
    if os.path.exists(url_model_path):
        url_model_data = joblib.load(url_model_path)
        print(f"Loaded URL Model: {url_model_data['model_name']}")
except Exception as e:
    print(f"Error loading URL model: {e}")

try:
    email_model_path = os.path.join(project_root, "models", "email_model.joblib")
    if os.path.exists(email_model_path):
        email_model_data = joblib.load(email_model_path)
        print("Loaded Email NLP Model")
except Exception as e:
    print(f"Error loading Email model: {e}")

try:
    metrics_path = os.path.join(project_root, "models", "metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path, "r", encoding="utf-8") as f:
            metrics_data = json.load(f)
except Exception as e:
    print(f"Error loading metrics: {e}")

telemetry = {
    "total_url_scans": 0,
    "total_email_scans": 0,
    "threats_blocked": 0,
    "warnings_issued": 0
}

class URLScanRequest(BaseModel):
    url: str = Field(..., json_schema_extra={"example": "http://paypa1-security-update.xyz/login"})

class EmailScanRequest(BaseModel):
    subject: str = Field(..., json_schema_extra={"example": "URGENT: Your account has been suspended"})
    sender: str = Field(default="", json_schema_extra={"example": "PayPal Support <service@security-alert.xyz>"})
    body: str = Field(..., json_schema_extra={"example": "Click here immediately: http://paypa1-security-update.xyz/login"})

@app.post("/api/scan/url")
def scan_url_endpoint(req: URLScanRequest):
    telemetry["total_url_scans"] += 1
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
        
    extracted = extract_url_features(url)
    features_dict = extracted["features"]
    indicators = extracted["indicators"]
    meta = extracted["meta"]
    
    ml_prob = 0.0
    if url_model_data:
        feature_vector = np.array([[features_dict[k] for k in url_model_data["features"]]])
        scaled_vector = url_model_data["scaler"].transform(feature_vector)
        clf = url_model_data["model"]
        if hasattr(clf, "predict_proba"):
            ml_prob = float(clf.predict_proba(scaled_vector)[0][1])
        else:
            ml_prob = float(clf.predict(scaled_vector)[0])
            
    risk_score, verdict, action = prevention.compute_url_risk_score(ml_prob, indicators, features_dict)
    defanged = prevention.defang_url(url)
    
    if verdict == "MALICIOUS":
        telemetry["threats_blocked"] += 1
        prevention.handle_detected_threat(
            target=url,
            threat_type="URL",
            risk_score=risk_score,
            details={
                "hostname": meta["hostname"],
                "verdict": verdict,
                "action": action,
                "indicators": indicators
            }
        )
    elif verdict == "SUSPICIOUS":
        telemetry["warnings_issued"] += 1

    return {
        "url": url,
        "defanged_url": defanged,
        "risk_score": risk_score,
        "verdict": verdict,
        "recommended_action": action,
        "ml_phishing_probability": round(ml_prob, 4),
        "risk_indicators": indicators,
        "metadata": meta,
        "key_features": {
            "is_ip": features_dict["is_ip"],
            "is_brand_spoofed": features_dict["is_brand_spoofed"],
            "target_brand": meta.get("target_brand"),
            "suspicious_tld": features_dict["is_suspicious_tld"],
            "url_entropy": features_dict["url_entropy"],
            "has_punycode": features_dict["has_punycode"]
        }
    }

@app.post("/api/scan/email")
def scan_email_endpoint(req: EmailScanRequest):
    telemetry["total_email_scans"] += 1
    
    email_analysis = extract_email_features(req.subject, req.body, req.sender)
    extracted_urls = email_analysis["extracted_urls"]
    
    scanned_urls = []
    url_risk_scores = []
    for u in extracted_urls:
        u_ext = extract_url_features(u)
        u_prob = 0.0
        if url_model_data:
            vec = np.array([[u_ext["features"][k] for k in url_model_data["features"]]])
            scaled = url_model_data["scaler"].transform(vec)
            clf = url_model_data["model"]
            if hasattr(clf, "predict_proba"):
                u_prob = float(clf.predict_proba(scaled)[0][1])
            else:
                u_prob = float(clf.predict(scaled)[0])
        u_score, u_verdict, u_action = prevention.compute_url_risk_score(u_prob, u_ext["indicators"], u_ext["features"])
        url_risk_scores.append(u_score)
        scanned_urls.append({
            "url": u,
            "defanged": prevention.defang_url(u),
            "risk_score": u_score,
            "verdict": u_verdict,
            "indicators": u_ext["indicators"]
        })
        
    full_text = f"{req.subject} {req.sender} {req.body}"
    ml_email_prob = 0.0
    if email_model_data:
        vec_text = email_model_data["vectorizer"].transform([full_text])
        clf = email_model_data["model"]
        if hasattr(clf, "predict_proba"):
            ml_email_prob = float(clf.predict_proba(vec_text)[0][1])
        else:
            ml_email_prob = float(clf.predict(vec_text)[0])
            
    risk_score, verdict, action = prevention.compute_email_risk_score(
        ml_email_prob, email_analysis["features"], url_risk_scores
    )
    
    all_indicators = list(email_analysis["indicators"])
    for u_res in scanned_urls:
        if u_res["verdict"] in ["MALICIOUS", "SUSPICIOUS"]:
            all_indicators.append(f"Embedded link '{u_res['defanged']}' rated as {u_res['verdict']} ({u_res['risk_score']}/100).")
            
    warning_banner = ""
    if verdict in ["PHISHING_MALICIOUS", "SUSPICIOUS_EMAIL"]:
        warning_banner = prevention.generate_email_warning_banner(risk_score, all_indicators)
        
    if verdict == "PHISHING_MALICIOUS":
        telemetry["threats_blocked"] += 1
        prevention.handle_detected_threat(
            target=f"Subject: {req.subject[:40]}... Sender: {req.sender}",
            threat_type="EMAIL",
            risk_score=risk_score,
            details={
                "verdict": verdict,
                "action": action,
                "indicators": all_indicators
            }
        )
    elif verdict == "SUSPICIOUS_EMAIL":
        telemetry["warnings_issued"] += 1

    return {
        "subject": req.subject,
        "sender": req.sender,
        "risk_score": risk_score,
        "verdict": verdict,
        "recommended_action": action,
        "ml_nlp_probability": round(ml_email_prob, 4),
        "risk_indicators": all_indicators,
        "sender_analysis": email_analysis["sender_analysis"],
        "scanned_links": scanned_urls,
        "warning_banner_html": warning_banner
    }

@app.get("/api/models/metrics")
def get_metrics():
    return metrics_data

@app.get("/api/telemetry/stats")
def get_telemetry():
    return {
        "counters": telemetry,
        "blocked_domains_count": len(prevention.blocked_domains),
        "quarantined_threats_count": len(prevention.quarantine_records),
        "active_models": {
            "url_classifier": url_model_data["model_name"] if url_model_data else "Not Loaded",
            "email_classifier": "Random Forest Email NLP (TF-IDF)" if email_model_data else "Not Loaded"
        }
    }

@app.get("/api/prevention/blocklist")
def get_blocklist(format: str = Query("hosts", enum=["hosts", "rpz", "adguard", "plain"])):
    content = prevention.export_blocklist(format)
    filename = f"phishing_blocklist.{format}.txt"
    return Response(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": f"inline; filename={filename}"}
    )

@app.get("/api/prevention/quarantine")
def get_quarantine():
    return prevention.quarantine_records[-50:]

@app.post("/api/simulate")
def get_simulation_vectors():
    return {
        "scenarios": [
            {
                "id": "sim-1",
                "title": "PayPal Credential Harvester (Typosquat)",
                "type": "URL",
                "payload": "http://paypa1-security-verification.xyz/login?session_id=89412",
                "description": "Uses typosquatting ('paypa1') and high-abuse TLD (.xyz) targeting financial credentials."
            },
            {
                "id": "sim-2",
                "title": "Microsoft 365 Urgent De-activation Lure",
                "type": "EMAIL",
                "payload": {
                    "subject": "CRITICAL ALERT: Your Microsoft 365 account expires in 2 hours",
                    "sender": "IT Support Team <admin-helpdesk@outlook-service.top>",
                    "body": "Your mailbox storage has exceeded organization limits. Click here immediately: http://login-microsoft365-portal.top/auth to preserve your active session."
                },
                "description": "Exploits manufactured time urgency (2 hours) and deceptive domain (.top)."
            },
            {
                "id": "sim-3",
                "title": "Raw IP Host Banking Phish",
                "type": "URL",
                "payload": "http://194.26.29.112:8080/chase/online-banking/verify.php",
                "description": "Bypasses domain registration entirely via raw IP address hosting on non-standard port."
            },
            {
                "id": "sim-4",
                "title": "Executive Wire Fraud / BEC",
                "type": "EMAIL",
                "payload": {
                    "subject": "Confidential: Emergency wire payment needed today",
                    "sender": "Chief Executive Officer <ceo-private@gmail.com>",
                    "body": "I am in an urgent offsite board meeting. Please immediately execute a wire transfer of $24,500 to our strategic partner. Do not call me, reply directly to this email."
                },
                "description": "Business Email Compromise (BEC) with sender display name spoofing using free Gmail webmail."
            },
            {
                "id": "sim-5",
                "title": "Legitimate Cloud Billing Statement",
                "type": "EMAIL",
                "payload": {
                    "subject": "Your monthly cloud usage statement is ready",
                    "sender": "Billing Notifications <billing@cloudprovider.com>",
                    "body": "Your statement for the current billing cycle is ready to view. Visit https://cloudprovider.com/console/billing to inspect itemized charges."
                },
                "description": "Normal, legitimate business communication with verified domain."
            },
            {
                "id": "sim-6",
                "title": "Legitimate Software Repository URL",
                "type": "URL",
                "payload": "https://github.com/scikit-learn/scikit-learn/releases/tag/1.4.0",
                "description": "Authentic enterprise HTTPS web URL."
            }
        ]
    }

@app.get("/", response_class=HTMLResponse)
def serve_index():
    index_path = os.path.join(project_root, "src", "web", "templates", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h2>AI Phishing Defense Console is ready. Index UI loading...</h2>")