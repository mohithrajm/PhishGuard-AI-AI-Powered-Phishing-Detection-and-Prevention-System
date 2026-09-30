# Prevention and Threat Defense Engine
import os
import json
import time
from datetime import datetime, timezone

class PreventionEngine:
    def __init__(self, blocklist_file="data/blocked_domains.json", quarantine_file="data/quarantine_log.json"):
        self.blocklist_file = blocklist_file
        self.quarantine_file = quarantine_file
        self.blocked_domains = set()
        self.quarantine_records = []
        self.load_data()

    def load_data(self):
        os.makedirs("data", exist_ok=True)
        if os.path.exists(self.blocklist_file):
            try:
                with open(self.blocklist_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.blocked_domains = set(data)
            except Exception:
                self.blocked_domains = set()
                
        if os.path.exists(self.quarantine_file):
            try:
                with open(self.quarantine_file, "r", encoding="utf-8") as f:
                    self.quarantine_records = json.load(f)
            except Exception:
                self.quarantine_records = []

    def save_data(self):
        with open(self.blocklist_file, "w", encoding="utf-8") as f:
            json.dump(list(self.blocked_domains), f, indent=2)
        with open(self.quarantine_file, "w", encoding="utf-8") as f:
            json.dump(self.quarantine_records[-100:], f, indent=2)

    def defang_url(self, url: str) -> str:
        """Defang URL for safe security analysis and transmission."""
        defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
        defanged = defanged.replace(".", "[.]")
        defanged = defanged.replace("://", "[://]")
        return defanged

    def compute_url_risk_score(self, ml_prob: float, indicators: list, features: dict) -> tuple:
        """
        Combine ML inference probability with heuristic threat signals to compute:
        (risk_score [0-100], verdict, policy_action)
        """
        # Base score from ML confidence (0-100)
        base_score = ml_prob * 85.0
        
        # Heuristic critical boosters
        booster = 0.0
        if features.get("is_brand_spoofed", 0) == 1:
            booster += 15.0
        if features.get("is_ip", 0) == 1:
            booster += 15.0
        if features.get("is_suspicious_tld", 0) == 1:
            booster += 10.0
        if features.get("num_at", 0) > 0:
            booster += 10.0
        if features.get("has_punycode", 0) == 1:
            booster += 15.0

        risk_score = min(100.0, round(base_score + booster, 1))

        if risk_score >= 70.0:
            verdict = "MALICIOUS"
            action = "BLOCK_AND_SINKHOLE"
        elif risk_score >= 35.0:
            verdict = "SUSPICIOUS"
            action = "WARN_USER"
        else:
            verdict = "SAFE"
            action = "ALLOW"

        return risk_score, verdict, action

    def compute_email_risk_score(self, ml_prob: float, email_features: dict, url_scores: list) -> tuple:
        """Compute multi-vector email risk score."""
        base_score = ml_prob * 70.0
        
        # Heuristics
        booster = 0.0
        if email_features.get("sender_is_spoofed", 0) == 1:
            booster += 20.0
        if email_features.get("urgency_score", 0) >= 2:
            booster += 10.0
        if email_features.get("deceptive_anchor_count", 0) >= 1:
            booster += 25.0
            
        # Max score of any embedded link
        if url_scores:
            max_url_score = max(url_scores)
            if max_url_score >= 70:
                booster += 25.0

        risk_score = min(100.0, round(base_score + booster, 1))
        
        if risk_score >= 70.0:
            verdict = "PHISHING_MALICIOUS"
            action = "QUARANTINE"
        elif risk_score >= 35.0:
            verdict = "SUSPICIOUS_EMAIL"
            action = "INSERT_WARNING_BANNER"
        else:
            verdict = "LEGITIMATE"
            action = "DELIVER_INBOX"
            
        return risk_score, verdict, action

    def handle_detected_threat(self, target: str, threat_type: str, risk_score: float, details: dict):
        """Execute automated prevention action: blocklist, quarantine, and log."""
        timestamp = datetime.now(timezone.utc).isoformat() + "Z"
        
        # If URL/Domain, add to blocked domains list
        if threat_type in ["URL", "DOMAIN"]:
            domain = details.get("hostname")
            if domain and not domain.startswith("127.") and not domain == "localhost":
                self.blocked_domains.add(domain)

        # Log to quarantine
        record = {
            "id": f"THREAT-{int(time.time()*1000)}",
            "timestamp": timestamp,
            "target": target,
            "threat_type": threat_type,
            "risk_score": risk_score,
            "verdict": details.get("verdict", "MALICIOUS"),
            "action_taken": details.get("action", "BLOCKED"),
            "indicators": details.get("indicators", [])
        }
        self.quarantine_records.append(record)
        self.save_data()
        return record

    def generate_email_warning_banner(self, risk_score: float, indicators: list) -> str:
        """Generate safe HTML banner injected into suspicious emails."""
        indicator_list_html = "".join(f"<li>• {ind}</li>" for ind in indicators[:3])
        banner = f"""
<div style="background-color: #ffebe6; border-left: 5px solid #de350b; padding: 12px 16px; margin: 10px 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 13px; color: #172b4d; border-radius: 4px;">
    <div style="font-weight: 700; color: #de350b; font-size: 14px; margin-bottom: 4px;">
        ⚠️ CAUTION: AI Phishing Guard Flagged Suspicious Communication (Risk Score: {risk_score}/100)
    </div>
    <div style="margin-bottom: 6px;">
        This message exhibits traits of social engineering or unauthorized spoofing. <strong>Never supply passwords, gift cards, or MFA codes.</strong>
    </div>
    <ul style="margin: 0; padding-left: 16px; color: #42526e; font-size: 12px;">
        {indicator_list_html}
    </ul>
</div>
"""
        return banner.strip()

    def export_blocklist(self, format_type: str = "hosts") -> str:
        """Export firewall / DNS blocklists in standard formats."""
        domains = sorted(list(self.blocked_domains))
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        if format_type == "hosts":
            lines = [
                f"# AI-Powered Phishing Defense System - Hosts Blocklist",
                f"# Generated: {now}",
                f"# Total Blocked Domains: {len(domains)}",
                ""
            ]
            for d in domains:
                lines.append(f"0.0.0.0 {d}")
            return "\n".join(lines)
            
        elif format_type == "rpz":
            lines = [
                f"; Response Policy Zone (RPZ) - AI Phishing Defense",
                f"; Generated: {now}",
                f"$TTL 300",
                f"@ IN SOA localhost. root.localhost. ({int(time.time())} 3600 600 86400 300)",
                f"  IN NS  localhost.",
                ""
            ]
            for d in domains:
                lines.append(f"{d} CNAME .")
                lines.append(f"*.{d} CNAME .")
            return "\n".join(lines)
            
        elif format_type == "adguard":
            lines = [
                f"! AdGuard / Pi-hole Filter List - AI Phishing Defense",
                f"! Generated: {now}",
                f"! Count: {len(domains)}",
                ""
            ]
            for d in domains:
                lines.append(f"||{d}^")
            return "\n".join(lines)
            
        return "\n".join(domains)