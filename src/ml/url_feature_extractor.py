# URL Feature Extractor
import re
import math
from urllib.parse import urlparse

TOP_BRANDS = [
    'google', 'microsoft', 'apple', 'amazon', 'paypal', 'netflix',
    'facebook', 'instagram', 'whatsapp', 'chase', 'wellsfargo',
    'bankofamerica', 'citibank', 'binance', 'coinbase', 'dropbox',
    'adobe', 'linkedin', 'twitter', 'yahoo', 'outlook', 'github',
    'ebay', 'spotify', 'steam', 'walmart'
]

LEGIT_BRAND_DOMAINS = {
    'google': ['google.com', 'google.co.uk', 'google.de', 'google.fr', 'google.ca'],
    'microsoft': ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
    'apple': ['apple.com', 'icloud.com'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp'],
    'paypal': ['paypal.com', 'paypal.me'],
    'netflix': ['netflix.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'instagram': ['instagram.com'],
    'whatsapp': ['whatsapp.com'],
    'chase': ['chase.com'],
    'wellsfargo': ['wellsfargo.com'],
    'bankofamerica': ['bankofamerica.com', 'bofa.com'],
    'citibank': ['citi.com', 'citibank.com'],
    'binance': ['binance.com'],
    'coinbase': ['coinbase.com'],
    'dropbox': ['dropbox.com'],
    'adobe': ['adobe.com'],
    'linkedin': ['linkedin.com'],
    'twitter': ['twitter.com', 'x.com'],
    'yahoo': ['yahoo.com'],
    'outlook': ['outlook.com', 'live.com', 'office365.com'],
    'github': ['github.com'],
    'ebay': ['ebay.com'],
    'spotify': ['spotify.com'],
    'steam': ['steampowered.com', 'steamcommunity.com'],
    'walmart': ['walmart.com']
}

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'work', 'fit', 'cn', 'ru', 'tk', 'ml', 'ga',
    'cf', 'gq', 'buzz', 'cam', 'live', 'guru', 'rest', 'casa', 'kim',
    'surf', 'monster', 'icu', 'bar', 'link'
}

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'update', 'banking', 'secure',
    'confirm', 'wallet', 'signin', 'password', 'support', 'billing',
    'service', 'alert', 'security', 'recovery', 'validation', 'suspended',
    'auth', 'authorize', 'free', 'bonus', 'prize', 'refund'
]

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def extract_domain_parts(url: str):
    normalized_url = url.strip()
    if not (normalized_url.startswith('http://') or normalized_url.startswith('https://')):
        normalized_url = 'http://' + normalized_url
    try:
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname or ''
        path = parsed.path or ''
        query = parsed.query or ''
        return parsed, hostname.lower(), path, query
    except Exception:
        return None, '', '', ''

def check_brand_spoofing(hostname: str):
    host_clean = hostname.split(':')[0]
    subdomains = host_clean.split('.')
    domain_core = subdomains[-2] if len(subdomains) >= 2 else host_clean
    
    spoofed_brand = None
    min_dist = 999
    tokens = [domain_core] + [t for t in re.split(r'[-_]', domain_core) if t]
    
    for brand, legit_domains in LEGIT_BRAND_DOMAINS.items():
        is_legit = any(host_clean == d or host_clean.endswith('.' + d) for d in legit_domains)
        if is_legit:
            return 0, None, False
            
        if brand in host_clean:
            return 1, brand, True
            
        for token in tokens:
            dist = levenshtein_distance(token, brand)
            if 0 < dist <= 2 and len(token) >= 4:
                if dist < min_dist:
                    min_dist = dist
                    spoofed_brand = brand
                
    if min_dist <= 2 and spoofed_brand:
        return 1, spoofed_brand, True
        
    return 0, None, False

def extract_url_features(url: str) -> dict:
    parsed, hostname, path, query = extract_domain_parts(url)
    url_len = len(url)
    domain_len = len(hostname)
    path_len = len(path)
    query_len = len(query)
    
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_underscores = url.count('_')
    num_slashes = url.count('/')
    num_questionmarks = url.count('?')
    num_equals = url.count('=')
    num_at = url.count('@')
    num_ampersand = url.count('&')
    num_exclamation = url.count('!')
    num_percent = url.count('%')
    
    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    digit_ratio = round(digits / max(url_len, 1), 4)
    letter_ratio = round(letters / max(url_len, 1), 4)
    
    url_entropy = shannon_entropy(url)
    domain_entropy = shannon_entropy(hostname)
    
    host_parts = [p for p in hostname.split('.') if p]
    count_subdomains = max(0, len(host_parts) - 2)
    
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    is_ip = 1 if re.match(ip_pattern, hostname) else 0
    
    has_port = 1 if (':' in parsed.netloc if parsed else False) and not is_ip else 0
    is_https = 1 if url.lower().startswith('https://') else 0
    
    tld = host_parts[-1] if host_parts else ''
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    
    url_lower = url.lower()
    keyword_matches = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    suspicious_keyword_count = len(keyword_matches)
    has_suspicious_keyword = 1 if suspicious_keyword_count > 0 else 0
    
    is_brand_spoofed, target_brand, direct_abuse = check_brand_spoofing(hostname)
    has_punycode = 1 if 'xn--' in hostname else 0
    has_double_slash = 1 if '//' in path else 0

    risk_indicators = []
    if is_ip:
        risk_indicators.append('Host is a direct raw IP address rather than a legitimate domain.')
    if is_brand_spoofed:
        risk_indicators.append(f'Potential typosquatting/brand impersonation detected targeting \'{target_brand}\'.')
    if is_suspicious_tld:
        risk_indicators.append(f'Top-Level Domain (.{tld}) has a high historical abuse rate.')
    if num_at > 0:
        risk_indicators.append('Contains \'@\' symbol which can obscure destination host in browsers.')
    if count_subdomains >= 3:
        risk_indicators.append(f'Abnormally deep subdomain structure ({count_subdomains} subdomains).')
    if suspicious_keyword_count >= 2:
        kw_sample = ", ".join(keyword_matches[:3])
        risk_indicators.append(f'Contains multiple sensitive keywords: {kw_sample}.')
    if has_punycode:
        risk_indicators.append('Uses Punycode (IDN) which is commonly employed in homograph attacks.')
    if domain_entropy > 4.2:
        risk_indicators.append('High domain name entropy suggests automated Domain Generation Algorithm (DGA).')
    if not is_https and (has_suspicious_keyword or is_brand_spoofed):
        risk_indicators.append('Insecure HTTP protocol used on a credential/sensitive page.')
        
    features_dict = {
        'url_length': url_len,
        'domain_length': domain_len,
        'path_length': path_len,
        'query_length': query_len,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_underscores': num_underscores,
        'num_slashes': num_slashes,
        'num_questionmarks': num_questionmarks,
        'num_equals': num_equals,
        'num_at': num_at,
        'num_ampersand': num_ampersand,
        'num_exclamation': num_exclamation,
        'num_percent': num_percent,
        'digit_ratio': digit_ratio,
        'letter_ratio': letter_ratio,
        'url_entropy': url_entropy,
        'domain_entropy': domain_entropy,
        'count_subdomains': count_subdomains,
        'is_ip': is_ip,
        'has_port': has_port,
        'is_https': is_https,
        'is_suspicious_tld': is_suspicious_tld,
        'suspicious_keyword_count': suspicious_keyword_count,
        'has_suspicious_keyword': has_suspicious_keyword,
        'is_brand_spoofed': is_brand_spoofed,
        'has_punycode': has_punycode,
        'has_double_slash': has_double_slash
    }
    
    return {
        'features': features_dict,
        'indicators': risk_indicators,
        'meta': {
            'hostname': hostname,
            'tld': tld,
            'target_brand': target_brand,
            'keyword_matches': keyword_matches
        }
    }

FEATURE_NAMES = [
    'url_length', 'domain_length', 'path_length', 'query_length',
    'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
    'num_questionmarks', 'num_equals', 'num_at', 'num_ampersand',
    'num_exclamation', 'num_percent', 'digit_ratio', 'letter_ratio',
    'url_entropy', 'domain_entropy', 'count_subdomains', 'is_ip',
    'has_port', 'is_https', 'is_suspicious_tld', 'suspicious_keyword_count',
    'has_suspicious_keyword', 'is_brand_spoofed', 'has_punycode',
    'has_double_slash'
]
