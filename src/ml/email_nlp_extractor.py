import re
from urllib.parse import urlparse

URGENCY_PATTERNS = [
    r'\b(immediately|urgent|urgently|suspended|suspend|terminate|terminated)\b',
    r'\b(act now|action required|final warning|attention required)\b',
    r'\b(24 hours|48 hours|within 24h|within 12 hours)\b',
    r'\b(unauthorized|unusual sign-in|unusual activity|compromised|breach)\b',
    r'\b(locked out|account locked|security notice|critical alert)\b',
    r'\b(failure to respond|legal action|lawsuit|penalty)\b',
    r'\b(wire transfer|gift card|crypto|bitcoin|payroll direct deposit)\b',
    r'\b(re-activate|verify identity|confirm details|validate account)\b'
]

CTA_PATTERNS = [
    r'\b(click here|log in here|login now|sign in here|sign in now)\b',
    r'\b(verify here|verify your account|update payment|update billing)\b',
    r'\b(reset password|change password|view document|download statement)\b',
    r'\b(claim refund|claim reward|claim prize|confirm transaction)\b'
]

FREE_WEBMAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
    'mail.com', 'proton.me', 'protonmail.com', 'zoho.com', 'icloud.com'
}

CORP_BRANDS = ['microsoft', 'paypal', 'apple', 'google', 'amazon', 'netflix', 'chase', 'bank of america']

def extract_urls_from_text(text: str) -> list:
    url_pattern = r'(https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+)'
    raw_urls = re.findall(url_pattern, text, re.IGNORECASE)
    cleaned = []
    for u in raw_urls:
        u_clean = u.rstrip('.,;!?:')
        if not u_clean.startswith('http'):
            u_clean = 'http://' + u_clean
        cleaned.append(u_clean)
    return cleaned

def analyze_sender_spoofing(sender_field: str) -> dict:
    if not sender_field:
        return {'is_spoofed': 0, 'reason': 'No sender specified'}
    
    match = re.search(r'(.*?)(?:<([^>]+)>|$)', sender_field.strip())
    display_name = ''
    email_addr = ''
    if match:
        display_name = (match.group(1) or '').strip(' "\'')
        email_addr = (match.group(2) or '').strip()
        if not email_addr and '@' in display_name:
            email_addr = display_name
            display_name = ''
            
    domain = email_addr.split('@')[-1].lower() if '@' in email_addr else ''
    
    display_lower = display_name.lower()
    for brand in CORP_BRANDS:
        if brand in display_lower:
            if domain in FREE_WEBMAIL_DOMAINS or (brand not in domain):
                return {
                    'is_spoofed': 1,
                    'reason': f'Display name claims to be "{brand.capitalize()}" but email domain is "{domain}".',
                    'display_name': display_name,
                    'email': email_addr,
                    'domain': domain
                }
                
    return {
        'is_spoofed': 0,
        'reason': 'Sender headers appear consistent',
        'display_name': display_name,
        'email': email_addr,
        'domain': domain
    }

def extract_email_features(subject: str, body: str, sender: str = '') -> dict:
    full_text = f'{subject} {body}'
    full_lower = full_text.lower()
    text_len = len(full_text)
    
    urgency_hits = []
    for pat in URGENCY_PATTERNS:
        matches = re.findall(pat, full_lower)
        if matches:
            urgency_hits.extend(matches)
    urgency_count = len(urgency_hits)
    
    cta_hits = []
    for pat in CTA_PATTERNS:
        matches = re.findall(pat, full_lower)
        if matches:
            cta_hits.extend(matches)
    cta_count = len(cta_hits)
    
    subj_len = max(len(subject), 1)
    subj_caps = sum(1 for c in subject if c.isupper())
    subj_caps_ratio = round(subj_caps / subj_len, 4)
    subj_exclamations = subject.count('!')
    
    urls = extract_urls_from_text(body)
    num_links = len(urls)
    link_density = round(num_links / max(text_len / 500, 1), 4)
    
    deceptive_anchor_count = 0
    html_link_pattern = r'<a\s+(?:[^>]*?\s+)?href=(["\'])(https?://.*?)\1[^>]*>(.*?)</a>'
    for match in re.finditer(html_link_pattern, body, re.IGNORECASE):
        href_url = match.group(2).lower()
        anchor_text = match.group(3).strip().lower()
        if anchor_text.startswith('http'):
            try:
                href_host = urlparse(href_url).hostname or ''
                text_host = urlparse(anchor_text).hostname or ''
                if href_host and text_host and href_host != text_host:
                    deceptive_anchor_count += 1
            except Exception:
                pass
                
    sender_analysis = analyze_sender_spoofing(sender)
    
    risk_indicators = []
    if urgency_count >= 2:
        risk_indicators.append(f'High psychological urgency/coercion markers detected ({urgency_count} instances).')
    if cta_count >= 1:
        risk_indicators.append('Contains high-pressure call-to-action urging credential/payment submission.')
    if sender_analysis.get('is_spoofed'):
        risk_indicators.append(sender_analysis['reason'])
    if deceptive_anchor_count > 0:
        risk_indicators.append(f'Detected {deceptive_anchor_count} deceptive hyperlinks where visible link text does not match actual destination URL.')
    if subj_caps_ratio > 0.4 and len(subject) > 10:
        risk_indicators.append('Subject line uses excessive capitalization to manufacture false urgency.')
    if num_links > 3:
        risk_indicators.append(f'High volume of embedded external hyperlinks ({num_links} links).')

    features = {
        'urgency_score': urgency_count,
        'cta_score': cta_count,
        'subj_caps_ratio': subj_caps_ratio,
        'subj_exclamations': subj_exclamations,
        'num_links': num_links,
        'link_density': link_density,
        'deceptive_anchor_count': deceptive_anchor_count,
        'sender_is_spoofed': sender_analysis.get('is_spoofed', 0)
    }
    
    return {
        'features': features,
        'indicators': risk_indicators,
        'sender_analysis': sender_analysis,
        'extracted_urls': urls
    }