# Dataset Generator for Phishing URLs and Emails
import os
import random
import csv

random.seed(42)

# Curated seed lists
LEGIT_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "netflix.com", "github.com", "wikipedia.org", "linkedin.com", "twitter.com",
    "reddit.com", "stackoverflow.com", "nytimes.com", "bbc.co.uk", "cnn.com",
    "dropbox.com", "spotify.com", "salesforce.com", "adobe.com", "zoom.us",
    "medium.com", "quora.com", "imdb.com", "nih.gov", "harvard.edu",
    "stanford.edu", "mit.edu", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "citi.com", "walmart.com", "target.com", "ebay.com", "etsy.com",
    "slack.com", "gitlab.com", "trello.com", "stripe.com", "cloudflare.com",
    "docker.com", "python.org", "apache.org", "mozilla.org", "w3schools.com",
    "oracle.com", "intel.com", "cisco.com", "ibm.com", "dell.com"
]

BENIGN_PATHS = [
    "", "/", "/about", "/contact", "/privacy-policy", "/terms", "/help",
    "/docs/quickstart", "/api/v1/users", "/search?q=machine+learning",
    "/products/laptops?sort=price_asc", "/articles/2026/03/technology-trends",
    "/blog/cybersecurity-fundamentals", "/news/finance/global-markets",
    "/download/latest-release", "/support/knowledge-base", "/courses/python-101",
    "/profile/settings", "/dashboard/overview", "/explore/popular", "/releases/v2.4.0"
]

TARGETED_BRANDS = [
    "paypal", "chase", "netflix", "apple", "amazon", "microsoft",
    "wellsfargo", "bankofamerica", "binance", "coinbase", "google", "meta"
]

PHISH_TLDS = ["xyz", "top", "club", "work", "live", "fit", "buzz", "icu", "surf", "cam", "rest", "bar"]
PHISH_KEYWORDS = ["login", "verify", "secure", "account", "update", "signin", "banking", "wallet", "confirm", "support"]

def generate_legitimate_url() -> str:
    domain = random.choice(LEGIT_DOMAINS)
    protocol = "https://" if random.random() < 0.92 else "http://"
    
    # Optional benign subdomain
    sub = ""
    if random.random() < 0.4:
        sub = random.choice(["www.", "api.", "docs.", "support.", "blog.", "dev."])
        
    path = random.choice(BENIGN_PATHS)
    if random.random() < 0.3 and path:
        path += f"&ref={random.choice(['social', 'email_digest', 'direct', 'search'])}&id={random.randint(1000, 9999)}"
        
    return f"{protocol}{sub}{domain}{path}"

def generate_phishing_url() -> str:
    attack_type = random.choice([
        "typosquatting", "subdomain_spoof", "ip_address", "tld_abuse",
        "keyword_stuffing", "homoglyph", "path_redirect"
    ])
    brand = random.choice(TARGETED_BRANDS)
    protocol = "http://" if random.random() < 0.65 else "https://"
    
    if attack_type == "typosquatting":
        # Typosquat brand: paypa1, amaz0n, micr0soft, netfl1x
        typo_map = {"a": ["4", "o"], "e": ["3"], "i": ["1", "l"], "o": ["0"], "l": ["1"], "s": ["5"]}
        typo_brand = list(brand)
        for idx, char in enumerate(typo_brand):
            if char in typo_map and random.random() < 0.5:
                typo_brand[idx] = random.choice(typo_map[char])
                break
        brand_str = "".join(typo_brand)
        tld = random.choice(["com", "net", "org"] + PHISH_TLDS)
        kw = random.choice(PHISH_KEYWORDS)
        return f"{protocol}{brand_str}-{kw}.{tld}/{kw}-session?auth_token={random.randint(10000, 99999)}"
        
    elif attack_type == "subdomain_spoof":
        # Legitimate brand used as subdomain of rogue host
        rogue_host = f"secure-auth{random.randint(10, 99)}.{random.choice(PHISH_TLDS)}"
        return f"{protocol}{brand}.com.{rogue_host}/signin/verify.php?target={brand}"
        
    elif attack_type == "ip_address":
        ip = f"{random.randint(100, 220)}.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}"
        port = f":{random.choice([8080, 8443, 8000, 8888])}" if random.random() < 0.4 else ""
        return f"http://{ip}{port}/{brand}/account-locked/verify.html"
        
    elif attack_type == "tld_abuse":
        tld = random.choice(PHISH_TLDS)
        kw1 = random.choice(PHISH_KEYWORDS)
        kw2 = random.choice(PHISH_KEYWORDS)
        return f"{protocol}{brand}-{kw1}-{kw2}.{tld}/index.html"
        
    elif attack_type == "keyword_stuffing":
        kws = "-".join(random.sample(PHISH_KEYWORDS, 3))
        return f"{protocol}{kws}-portal.{random.choice(PHISH_TLDS)}/service/billing-update"
        
    elif attack_type == "homoglyph":
        return f"{protocol}xn--{brand}-login.{random.choice(PHISH_TLDS)}/auth?user=security"
        
    else:  # path_redirect
        legit_dom = random.choice(["tinyurl.com", "bit.ly", "freehost.net", "redirect-portal.org"])
        return f"http://{legit_dom}/redirect.php?url=http://{brand}-security-update.{random.choice(PHISH_TLDS)}/login"

def build_urls_dataset(num_samples: int = 4000, output_path: str = "data/urls_dataset.csv"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    samples = []
    
    half = num_samples // 2
    for _ in range(half):
        samples.append((generate_legitimate_url(), 0))
    for _ in range(half):
        samples.append((generate_phishing_url(), 1))
        
    random.shuffle(samples)
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for url, label in samples:
            writer.writerow([url, label])
            
    print(f"Generated {len(samples)} URLs dataset at {output_path}")

LEGIT_EMAILS = [
    {
        "subject": "Sprint planning sync for upcoming sprint",
        "sender": "Alice Walker <alice@acmecorp.com>",
        "body": "Hi team, please find the agenda for our bi-weekly sprint planning attached. We will review tickets on Jira and finalize estimations. Let me know if you need any adjustments to the schedule."
    },
    {
        "subject": "Your monthly cloud usage statement is ready",
        "sender": "Billing Notifications <billing@cloudprovider.com>",
        "body": "Hello, your monthly invoice for compute and storage resources is now available. You can view the summary in your account console under Billing > Statements. No action is required if automatic debit is enabled."
    },
    {
        "subject": "Weekly Tech Newsletter: Innovations in AI",
        "sender": "Tech Digest <newsletter@techinsider.org>",
        "body": "Here is your weekly summary of top technology news: advancements in machine learning architectures, modern open source libraries, and tips for distributed systems. Read the full stories on our publication portal."
    },
    {
        "subject": "Invitation: Team lunch this Friday",
        "sender": "HR Team <events@company.internal>",
        "body": "Hi everyone, we are organizing a team lunch this Friday at 12:30 PM to celebrate our project milestone. Please RSVP on the calendar invite so we can confirm the table reservation."
    },
    {
        "subject": "Code review requested: feature/auth-middleware",
        "sender": "GitHub <notifications@github.com>",
        "body": "Bob has requested your review on pull request #142: 'Implement token validation middleware'. Please visit the repository to inspect diffs and approve or leave comments."
    },
    {
        "subject": "Meeting notes & follow-up items from quarterly review",
        "sender": "David Chen <dchen@enterprise.org>",
        "body": "Thank you all for participating in today's quarterly sync. Attached are the summarized notes, action items, and assigned deadlines. Please review section 3 for marketing deliverables."
    }
]

PHISH_EMAILS = [
    {
        "subject": "URGENT: Your account has been suspended due to unauthorized activity!",
        "sender": "PayPal Security Support <service-notice@account-verify-sec.xyz>",
        "body": "Dear Customer, We detected an unauthorized login attempt on your account from an unknown IP address. For your security, your account access has been restricted. You must ACT NOW within 24 hours to confirm your identity. Failure to respond will result in permanent account termination. Click here: http://paypal-verify-account.xyz/login to verify your billing information immediately."
    },
    {
        "subject": "CRITICAL ALERT: Immediate password reset required for your Microsoft 365",
        "sender": "Microsoft IT Helpdesk <admin-support@outlook-service-alert.top>",
        "body": "ACTION REQUIRED: A critical security vulnerability was identified in your mailbox. Your password expires in 2 hours. Log in here immediately: http://login-microsoft365-portal.top/auth to keep your mailbox active and prevent data loss."
    },
    {
        "subject": "Pending Wire Transfer Confirmation - Immediate Action Needed",
        "sender": "CEO Office <executive-urgent@ceo-desk-transfer.fit>",
        "body": "I am currently in an urgent offsite meeting and need you to process an emergency wire transfer to our international vendor right away. Please confirm your availability and click here: http://wire-transfer-portal.fit/confirm to process payment before end of banking day."
    },
    {
        "subject": "Tax Refund Notification: Claim your $1,420 pending rebate",
        "sender": "Internal Revenue Service <refunds@irs-tax-claim.icu>",
        "body": "Our records indicate you are eligible for an unclaimed tax refund of $1,420.50. To receive your refund directly into your bank account, submit your banking credentials and card details here: http://tax-refund-gov-service.icu/claim. This link will expire in 24 hours."
    },
    {
        "subject": "Security Notice: Suspicious transaction of $849.99 detected",
        "sender": "Amazon Prime Alert <order-verification@amazon-tracking-order.live>",
        "body": "We noticed an unauthorized order for iPhone 16 placed on your account. If you did not authorize this charge, cancel transaction immediately by verifying your credentials at http://amazon-fraud-cancellation.live/verify."
    },
    {
        "subject": "Final Warning: Mailbox quota exceeded - Emails blocked",
        "sender": "IT Systems Administrator <postmaster@server-quota-check.cam>",
        "body": "Your email storage is 99% full. Incoming messages will be bounced immediately. Upgrade your storage quota for free within 12 hours by clicking here: http://webmail-storage-upgrade.cam/login or your email will be deactivated."
    }
]

def build_emails_dataset(num_samples: int = 1200, output_path: str = "data/emails_dataset.csv"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    samples = []
    
    half = num_samples // 2
    # Generate variations
    for _ in range(half):
        template = random.choice(LEGIT_EMAILS)
        samples.append((template["subject"], template["sender"], template["body"], 0))
        
    for _ in range(half):
        template = random.choice(PHISH_EMAILS)
        # Inject randomized tokens/variations
        body = template["body"].replace("24 hours", f"{random.choice([12, 24, 48])} hours")
        samples.append((template["subject"], template["sender"], body, 1))
        
    random.shuffle(samples)
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["subject", "sender", "body", "label"])
        for subj, snd, bdy, lbl in samples:
            writer.writerow([subj, snd, bdy, lbl])
            
    print(f"Generated {len(samples)} Emails dataset at {output_path}")

if __name__ == "__main__":
    build_urls_dataset(4000)
    build_emails_dataset(1200)