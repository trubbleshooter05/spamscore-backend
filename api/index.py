# ===========================
# api/index.py — V3.2 (Restored Missing Function + Fixed Forward Reading)
# ===========================

import os
import re
import html
import math
import json
import hashlib
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple, Set

from fastapi import FastAPI, Query, Form, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import tldextract
from redis import Redis

# ==============================================================================
# CONFIGURATION & SETUP
# ==============================================================================

# Use read-only friendly extractor on Vercel
_TLDX = tldextract.TLDExtract(cache_dir=None)

# Initialize FastAPI
app = FastAPI()

# Enable CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://spamscore-dashboard.vercel.app",
        "http://localhost:3000",
        "http://localhost:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Vercel KV / Redis Setup
KV_URL = os.getenv("KV_URL", "")
redis_client = None

if KV_URL:
    try:
        redis_client = Redis.from_url(KV_URL, decode_responses=True)
    except Exception as e:
        print(f"Redis connection failed: {e}")

# API Keys & Config
MG_KEY = os.getenv("MAILGUN_API_KEY", "")
MG_DOMAIN = os.getenv("MAILGUN_DOMAIN", "")
REPLY_FROM = os.getenv("REPLY_FROM", "scan@mg.techamped.com")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

# Tuning Constants
MIN_BLOCK_SCORE = int(os.getenv("MIN_BLOCK_SCORE", "15"))
MIN_CONFIDENCE = float(os.getenv("MIN_CONFIDENCE", "0.00"))
STRICT_BAD_TLD = True
ENABLE_TIPS = True
FORWARDED_PREFER_ORIGINAL = True

# Internal Placeholder for logic
UNKNOWN_SENDER_PLACEHOLDER = "unknown_sender_hidden@scan.system"

# ==============================================================================
# DATA MODELS
# ==============================================================================

class ScanBody(BaseModel):
    sender: str
    subject: str = ""
    email_text: str = ""

class WhitelistAddRequest(BaseModel):
    user_email: str
    type: str
    value: str

class WhitelistRemoveRequest(BaseModel):
    user_email: str
    type: str
    value: str

class BlocklistAddRequest(BaseModel):
    user_email: str
    type: str
    value: str

class BlocklistRemoveRequest(BaseModel):
    user_email: str
    type: str
    value: str

# ==============================================================================
# DICTIONARIES & VOCABULARY
# ==============================================================================

SUSPICIOUS_TLDS = {
    "xyz", "click", "top", "ru", "cn", "icu", "zip", "mov", "quest", "gq",
    "country", "work", "fit", "tk", "cf", "ml", "ga", "pw", "cc", "win",
    "bid", "loan", "date", "review", "party", "cam"
}

FREE_EMAIL_SENDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", 
    "icloud.com", "aol.com", "protonmail.com", "mail.com"
}

TRUSTED_DOMAINS = {
    "salesforce.com", "sonicwall.com", "microsoft.com", "google.com",
    "amazon.com", "apple.com", "adobe.com", "dropbox.com", "slack.com",
    "github.com", "gitlab.com", "atlassian.com", "zoom.us", "teams.microsoft.com",
    "linkedin.com", "twitter.com", "facebook.com", "instagram.com",
    "paypal.com", "stripe.com", "square.com", "shopify.com",
    "netflix.com", "spotify.com", "youtube.com", "twitch.tv",
    "airbnb.com", "uber.com", "lyft.com", "doordash.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "citi.com",
    "nasa.gov", "gov.uk", "edu", "arkay.com", "nytimes.com"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly",
    "adf.ly", "short.link", "tiny.cc", "is.gd", "cli.gs", "amzn.to",
    "tr.im", "lc.chat"
}

PHISHING_WORDS = [
    r"verify your account", r"reset your password", r"unauthorized login",
    r"unusual activity", r"update payment", r"wire transfer",
    r"crypto wallet", r"bank account", r"urgent action required",
    r"confirm your identity", r"2fa.*disable", r"limited time verification",
    r"suspended.*account", r"account.*locked", r"account.*limited",
    r"reactivate.*account", r"unusual.*activity", r"security.*alert"
]

JUNK_WORDS = [
    r"unsubscribe", r"newsletter", r"flash sale", r"discount", r"coupon",
    r"special offer", r"bundle", r"limited time", r"promo", r"view in browser",
    r"no[- ]?reply", r"do not reply", r"manage preferences",
    r"act fast", r"act now", r"hurry", r"don't miss", r"don't wait",
    r"\d{1,3}%\s*off", r"\bsale\b", r"clearance", r"\bdeals?\b",
    r"shop now", r"buy now", r"order now", r"get it now",
    r"exclusive offer", r"today only", r"expires", r"last chance",
    r"free shipping", r"lowest price", r"limited quantity",
    r"while supplies last", r"final hours", r"ending soon"
]

BUSINESS_SPAM_WEIGHTS = {
    r"\blead generation\b": 20, r"\bappointment setting\b": 20,
    r"\bqualified leads?\b": 20, r"\bdemand generation\b": 15,
    r"\bb2b outreach\b": 15, r"\brevops\b|\bsalesops\b": 15,
    r"\bscale your (team|revenue|sales)\b": 15, r"\bwhite label\b": 15,
    r"\boffshore team\b": 15, r"\boutsourcing\b": 15,
    r"\bhir(e|ing) (developers?|engineers?|designers?)\b": 10,
    r"\bstaff(ing)?\b": 10, r"\brecruit(er|ment|ing)\b": 10,
    r"\bnearshore\b|\boffshore\b": 10, r"\boutsourc(e|ing)\b": 10,
    r"\bfractional (cto|cmo|cfo)\b": 10, r"\bbook(ing)? a (call|demo)\b": 10,
    r"\bseo ranking\b": 10, r"\bfirst page of google\b": 10,
    r"\bweb development\b": 10, r"\breach(ing)? out\b": 5,
    r"\bagency\b": 5, r"\bcase study\b": 5, r"\bproposal\b|\brfp\b": 5,
    r"\baudit of your\b": 5, r"\bcalendar link\b": 5,
    r"\btalent\s+ready\b": 5, r"\bcollaboration\b": 5,
    r"\bpartnership\b": 5
}

SPAM_VOCAB = {
    "free": 10, "win": 8, "winner": 5, "prize": 7, "claim": 6, "urgent": 9,
    "limited": 8, "offer": 10, "deal": 7, "subscribe": 5, "unsubscribe": 10,
    "click": 9, "buy": 8, "sex": 5, "viagra": 5, "pharmacy": 5, "bitcoin": 6,
    "crypto": 6, "investment": 7, "guaranteed": 8, "million": 5, "dollars": 5,
    "cash": 7, "credit": 6, "loan": 6, "now": 10, "risk-free": 7, "congratulations": 7,
    "selected": 6, "special": 8, "promotion": 8, "seo": 8, "marketing": 7,
    "growth": 7, "generate": 7, "leads": 8, "revenue": 6, "traffic": 7,
    "ranking": 7, "outsource": 9, "offshore": 9, "development": 6, "hiring": 6,
    "dedicated": 5, "team": 5, "proposal": 6, "partnership": 6, "collaboration": 5,
    "opt-out": 8, "remove": 5, "list": 5, "database": 6, "verify": 7, "account": 5,
    "suspended": 8, "locked": 8, "action": 7, "required": 6, "immediately": 7,
    "bonus": 8, "exclusive": 7, "opportunity": 6, "passive": 7, "income": 7,
    "calendar": 6, "meeting": 5, "call": 5, "zoom": 5, "demo": 6, "audit": 6,
    "complimentary": 7, "gift": 7, "vouchers": 7, "rates": 5, "quota": 6
}

HAM_VOCAB = {
    "meeting": 10, "project": 9, "team": 8, "document": 8, "attached": 9,
    "update": 7, "report": 7, "schedule": 6, "discussion": 7, "feedback": 6,
    "request": 7, "question": 8, "following": 5, "invoice": 5, "payment": 5,
    "reminder": 6, "thanks": 10, "best": 8, "regards": 10, "sincerely": 8,
    "forwarded": 5, "link": 5, "issue": 6, "bug": 5, "fix": 5,
    "pull": 5, "merge": 5, "commit": 5
}

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def get_user_id_from_email(email: str) -> str:
    return hashlib.sha256(email.lower().encode()).hexdigest()[:16]

def extract_email(sender: str) -> str:
    match = re.search(r'<([^>]+)>', sender)
    if match:
        return match.group(1).lower().strip()
    return sender.lower().strip()

def extract_display_name(sender: str) -> Optional[str]:
    match = re.search(r'^([^<]+)<', sender)
    if match:
        name = match.group(1).strip().strip('"').strip("'")
        if name and '@' not in name: return name
    return None

def _domain_of(addr: str) -> str:
    try: return (addr or "").split("@", 1)[-1].lower()
    except Exception: return ""

def extract_urls(text: str) -> List[str]:
    return re.findall(r'https?://[^\s<>()"\'?]+', text)

def _is_all_caps(s: str) -> bool:
    s = (s or "").strip()
    letters = re.sub(r"[^A-Za-z]+", "", s)
    return bool(letters) and letters.isupper()

def validate_email_format(email: str) -> bool:
    if not email or len(email) > 254: return False
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    return bool(email_pattern.match(email))

# ==============================================================================
# DATABASE OPERATIONS (Redis)
# ==============================================================================

def get_whitelist_key(user_id: str, wl_type: str) -> str:
    return f"whitelist:{user_id}:{wl_type}"

def get_blocklist_key(user_id: str, bl_type: str) -> str:
    return f"blocklist:{user_id}:{bl_type}"

def add_to_whitelist(user_id: str, value: str, wl_type: str = 'email') -> bool:
    if not redis_client: return False
    try:
        key = get_whitelist_key(user_id, wl_type)
        redis_client.sadd(key, value.lower())
        redis_client.hset(f"{key}:meta:{value.lower()}", mapping={
            'added_at': datetime.now(timezone.utc).isoformat(),
            'type': wl_type, 'value': value.lower()
        })
        redis_client.srem(get_blocklist_key(user_id, wl_type), value.lower())
        return True
    except Exception: return False

def remove_from_whitelist(user_id: str, value: str, wl_type: str = 'email') -> bool:
    if not redis_client: return False
    try:
        key = get_whitelist_key(user_id, wl_type)
        redis_client.srem(key, value.lower())
        redis_client.delete(f"{key}:meta:{value.lower()}")
        return True
    except Exception: return False

def is_whitelisted(user_id: str, value: str, wl_type: str = 'email') -> bool:
    if not redis_client: return False
    return redis_client.sismember(get_whitelist_key(user_id, wl_type), value.lower())

def get_whitelist(user_id: str, wl_type: str = 'email') -> Set[str]:
    if not redis_client: return set()
    return redis_client.smembers(get_whitelist_key(user_id, wl_type))

def check_whitelist(user_id: str, sender: str) -> tuple[bool, str]:
    if not redis_client: return False, ""
    sender_email = extract_email(sender)
    sender_domain = _domain_of(sender_email)
    sender_name = extract_display_name(sender)
    
    if is_whitelisted(user_id, sender_email, 'email'):
        return True, f"whitelisted_email:{sender_email}"
    if is_whitelisted(user_id, sender_domain, 'domain'):
        return True, f"whitelisted_domain:{sender_domain}"
    if sender_name and is_whitelisted(user_id, sender_name.lower(), 'sender_name'):
        return True, f"whitelisted_sender_name:{sender_name}"
    return False, ""

def add_to_blocklist(user_id: str, value: str, bl_type: str = 'email') -> bool:
    if not redis_client: return False
    try:
        key = get_blocklist_key(user_id, bl_type)
        redis_client.sadd(key, value.lower())
        redis_client.hset(f"{key}:meta:{value.lower()}", mapping={
            'added_at': datetime.now(timezone.utc).isoformat(),
            'type': bl_type, 'value': value.lower()
        })
        redis_client.srem(get_whitelist_key(user_id, bl_type), value.lower())
        return True
    except Exception: return False

def remove_from_blocklist(user_id: str, value: str, bl_type: str = 'email') -> bool:
    if not redis_client: return False
    try:
        key = get_blocklist_key(user_id, bl_type)
        redis_client.srem(key, value.lower())
        redis_client.delete(f"{key}:meta:{value.lower()}")
        return True
    except Exception: return False

def is_blocked(user_id: str, value: str, bl_type: str = 'email') -> bool:
    if not redis_client: return False
    return redis_client.sismember(get_blocklist_key(user_id, bl_type), value.lower())

def check_blocklist(user_id: str, sender: str) -> tuple[bool, str]:
    if not redis_client: return False, ""
    sender_email = extract_email(sender)
    sender_domain = _domain_of(sender_email)
    
    if is_blocked(user_id, sender_email, 'email'):
        return True, f"blocked_email:{sender_email}"
    if is_blocked(user_id, sender_domain, 'domain'):
        return True, f"blocked_domain:{sender_domain}"
    return False, ""

def get_blocklist_count(user_id: str) -> int:
    if not redis_client: return 0
    return (redis_client.scard(f"blocklist:{user_id}:email") or 0) + \
           (redis_client.scard(f"blocklist:{user_id}:domain") or 0)

# ========= Stats & History =========

def record_scan(user_id: str, scan_id: str, sender: str, subject: str, score: int, 
                verdict: str, category: str, whitelisted: bool, blocked: bool = False):
    if not redis_client: return
    try:
        timestamp = datetime.now(timezone.utc)
        scan_key = f"scan:{user_id}:{scan_id}"
        redis_client.hset(scan_key, mapping={
            'id': scan_id, 'sender': sender, 'subject': subject or "No subject",
            'score': score, 'verdict': verdict, 'category': category,
            'whitelisted': str(whitelisted).lower(), 'blocked': str(blocked).lower(),
            'timestamp': timestamp.isoformat()
        })
        redis_client.expire(scan_key, 7776000)
        redis_client.zadd(f"scan_history:{user_id}", {scan_key: timestamp.timestamp()})
        monthly_key = f"stats:{user_id}:scans:{timestamp.strftime('%Y-%m')}"
        redis_client.incr(monthly_key)
        redis_client.expire(monthly_key, 2678400)
    except Exception as e: print(f"Failed to record scan: {e}")

def get_scan_history(user_id: str, limit: int = 50) -> List[Dict]:
    if not redis_client: return []
    try:
        history_keys = redis_client.zrevrange(f"scan_history:{user_id}", 0, limit - 1)
        history = []
        for key in history_keys:
            scan_data = redis_client.hgetall(key)
            if scan_data:
                history.append({
                    "id": scan_data.get("id", ""), "date": scan_data.get("timestamp", ""),
                    "sender": scan_data.get("sender", "Unknown"),
                    "subject": scan_data.get("subject", "No subject"),
                    "verdict": scan_data.get("verdict", ""),
                    "score": int(scan_data.get("score", 0)),
                    "whitelisted": scan_data.get("whitelisted", "false") == "true",
                    "blocked": scan_data.get("blocked", "false") == "true"
                })
        return history
    except Exception: return []

def get_monthly_scan_count(user_id: str) -> int:
    if not redis_client: return 0
    try:
        return int(redis_client.get(f"stats:{user_id}:scans:{datetime.now().strftime('%Y-%m')}") or 0)
    except Exception: return 0

# ==============================================================================
# SPAM ANALYSIS LOGIC
# ==============================================================================

def get_simple_explanation(reason_key: str) -> str:
    explanations = {
        "phishing_language": "Suspicious Phishing Keywords",
        "marketing_language": "Marketing/Sales Language",
        "business_spam": "B2B / Cold Outreach Pattern",
        "free_email_cold_outreach": "Business Outreach from Free Email",
        "free_email_business_content": "Business Content from Free Email",
        "free_email_with_unsubscribe": "Free Email with Unsubscribe Link",
        "poor_grammar": "Poor Grammar/Spelling",
        "tracking_urls_detected": "Tracking Links Detected",
        "suspicious_tld_detected": "Suspicious Domain (.xyz, .ru, etc)",
        "suspicious_link_tld": "Link to Suspicious Domain",
        "gibberish_domain_link": "Link to Gibberish Domain",
        "long_query_string_urls": "Complex Tracking URLs",
        "url_shorteners_detected": "URL Shortener Used",
        "all_caps_subject": "Aggressive ALL CAPS Subject",
        "urgency_pressure": "Urgency/Pressure Tactics",
        "generic_greeting": "Generic Greeting",
        "reply_to_mismatch": "Reply-To Address Mismatch",
        "microsoft_marked_as_spam": "Flagged by Microsoft Exchange",
        "spam_filter_verdict_spam": "Flagged by Upstream Filter",
        "categorized_as_spam": "Categorized as Spam",
        "delivered_to_junk_folder": "Originally delivered to Junk",
        "forefront_spam_detection": "Forefront Security Flag",
        "spamassassin_score": "High SpamAssassin Score",
        "barracuda_spam_score_high": "High Barracuda Score",
        "generic_cold_outreach_subject": "Cold Outreach Subject Line",
        "sender_name_email_mismatch": "Sender Name/Email Mismatch",
        "whitelisted_email": "Sender in Your Whitelist",
        "whitelisted_domain": "Domain in Your Whitelist", 
        "whitelisted_sender_name": "Sender Name in Whitelist",
        "whitelisted_score_reduced": "Whitelist Bonus Applied",
        "blocked_email": "Sender in Blocklist",
        "blocked_domain": "Domain in Blocklist",
        "malicious_url_detected": "MALICIOUS URL DETECTED",
        "forwarded_unsubscribe_header": "Unsubscribe Header Detected",
        "marketing_unsubscribe_link_in_body": "Unsubscribe Link in Body",
        "high_link_density": "High Density of Links",
        "bayesian_spam_content": "Content Analysis (Spam Pattern)",
        "bayesian_ham_bonus": "Content Analysis (Legitimate Pattern)",
        "trusted_domain_bonus": "Trusted Domain Bonus",
        "trusted_sender_bonus": "Trusted Sender Bonus",
        "unverified_sender_source": "Sender Could Not Be Verified",
        "lead_gen_spam": "Lead Generation Spam",
        "outsourcing_spam": "Outsourcing/Offshore Spam",
        "cold_call_request": "Cold Call/Meeting Request"
    }
    key_base = reason_key.split(":")[0]
    return explanations.get(key_base, reason_key.replace("_", " ").title())

def calculate_bayesian_score(text: str) -> float:
    text_words = set(re.findall(r'\b\w+\b', text.lower()))
    total_spam = sum(SPAM_VOCAB.values())
    total_ham = sum(HAM_VOCAB.values())
    vocab_size = len(set(SPAM_VOCAB.keys()) | set(HAM_VOCAB.keys()))
    
    log_spam = math.log(0.5)
    log_ham = math.log(0.5)
    
    for word in text_words:
        if len(word) > 2 and len(word) < 20:
            p_word_spam = (SPAM_VOCAB.get(word, 0) + 1) / (total_spam + vocab_size)
            log_spam += math.log(p_word_spam)
            p_word_ham = (HAM_VOCAB.get(word, 0) + 1) / (total_ham + vocab_size)
            log_ham += math.log(p_word_ham)

    score = (log_spam - log_ham) * 3.0
    return max(-10.0, min(40.0, score))

def _url_features(urls: List[str]) -> Tuple[bool, bool, bool, List[str]]:
    tracking_hit = False; bad_tld_hit = False; long_query_hit = False; shortener_urls = []
    for u in urls:
        try:
            parsed = urlparse(u)
            host = parsed.netloc.lower()
            if any(hint in host for hint in ["click", "trk", "track", "r.", "l.", "links."]): tracking_hit = True
            if _TLDX(u).suffix in SUSPICIOUS_TLDS: bad_tld_hit = True
            if len(parsed.query) > 80: long_query_hit = True
            if host in URL_SHORTENERS: shortener_urls.append(u)
        except Exception: pass
    return tracking_hit, bad_tld_hit, long_query_hit, shortener_urls

async def check_urls_against_safe_browsing(urls: List[str]) -> Tuple[bool, List[str]]:
    if not GOOGLE_SAFE_BROWSING_API_KEY or not urls: return False, []
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {"clientId": "spamscore", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"], "threatEntries": [{"url": url} for url in urls[:10]]
            }
        }
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(api_url, json=payload)
            if r.status_code == 200 and r.json().get("matches"):
                return True, [m.get("threat", {}).get("url") for m in r.json().get("matches")]
        return False, []
    except Exception: return False, []

def check_domain_spamhaus_dbl(domain: str) -> bool:
    """
    Check if domain is listed in Spamhaus DBL (Domain Block List).
    Returns True if domain is listed (bad reputation).
    """
    if not domain or '.' not in domain:
        return False
    try:
        # Query Spamhaus DBL via DNS
        query = f"{domain}.dbl.spamhaus.org"
        socket.gethostbyname(query)
        return True  # If resolution succeeds, domain is listed
    except socket.gaierror:
        return False  # Not listed
    except Exception:
        return False

async def check_url_urlhaus(url: str) -> bool:
    """
    Check if URL is listed in URLhaus (malicious URL database).
    Returns True if URL is malicious.
    """
    if not url:
        return False
    try:
        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        payload = {"url": url}
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(api_url, data=payload)
            if r.status_code == 200:
                data = r.json()
                # URLhaus returns query_status: "ok" if URL is in their database
                return data.get("query_status") == "ok"
        return False
    except Exception:
        return False

# ==============================================================================
# FORWARD DETECTION (Improved)
# ==============================================================================

def detect_forwarded_original_sender(body: str) -> tuple[str, str] | None:
    """
    Attempts to find the original sender in a forwarded email.
    Returns: (email, display_name) or None
    """
    if not body: return None
    clean = body.replace("*", "").strip()

    # FIRST: Try to extract email AND display name from angle brackets in "From:" line
    # This handles: "From: Mixcloud <noreply@mixcloudmail.com>" format
    angle_bracket_pattern = r'From:\s*([^<\n]*?)\s*<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>'
    angle_match = re.search(angle_bracket_pattern, clean, re.IGNORECASE | re.MULTILINE)
    if angle_match:
        display_name = angle_match.group(1).strip()
        email = angle_match.group(2).lower().strip()
        if email and '@' in email:
            return (email, display_name)

    # Strip HTML tags AND email quote markers (>, >>, etc.) for better pattern matching
    html_stripped = re.sub(r'<[^>]+>', ' ', clean)
    quote_stripped = re.sub(r'^[>\s]+', '', html_stripped, flags=re.MULTILINE)  # Remove > prefixes from lines

    # 1. Strict Patterns (Best quality) - handles various formats (no display name)
    patterns = [
        r'From:.*?\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',
        r'Sender:\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?',
        r'\bFrom:\s+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        r'>+\s*From:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  # Quoted forward (> From:)
    ]

    # Try patterns on quote-stripped version first (best for plain text forwards)
    for pattern in patterns:
        match = re.search(pattern, quote_stripped, re.IGNORECASE)
        if match:
            email = match.group(1).lower().strip()
            if email and '@' in email: return (email, "")

    # Try patterns on HTML-stripped version
    for pattern in patterns:
        match = re.search(pattern, html_stripped, re.IGNORECASE)
        if match:
            email = match.group(1).lower().strip()
            if email and '@' in email: return (email, "")

    # Try patterns on original body as final fallback
    for pattern in patterns:
        match = re.search(pattern, clean, re.IGNORECASE | re.DOTALL)
        if match:
            email = match.group(1).lower().strip()
            if email and '@' in email: return (email, "")

    # 2. Loose Fallback: Find ANY email in the first 2000 chars (no display name)
    header_chunk = quote_stripped[:2000]
    emails = re.findall(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', header_chunk)

    for email in emails:
        email = email.lower()
        # Exclude common system emails and scanning system
        if any(x in email for x in ["support@", "bounce", "daemon", "scan@", "noreply@"]):
            continue
        return (email, "")
    return None

def detect_marketing_email(body: str, subject: str) -> List[Tuple[str, int]]:
    contribs = []
    combined = f"{subject} {body}".lower()
    
    if 'list-unsubscribe:' in combined:
        contribs.append(("forwarded_unsubscribe_header", 40))
    
    if "unsubscribe" in combined:
        if any(x in combined for x in ["click here", "preferences", "opt-out", "browser", "subscription", "manage"]):
            contribs.append(("marketing_unsubscribe_link_in_body", 40))
            
    if re.search(r'precedence\s*:\s*bulk', combined):
        contribs.append(("precedence_bulk_header", 20))
    
    if re.search(r'\d{1,3}%\s*off', combined):
        contribs.append(("discount_offer", 15))
        
    if re.search(r'act fast|limited time|hurry|expires', combined):
        contribs.append(("urgency_tactics", 20))
        
    return contribs

# 🔴 RESTORED FUNCTION
def analyze_email_headers(body: str) -> List[Tuple[str, int]]:
    contributions = []
    if not body: return []
    body_lower = body.lower()
    
    if re.search(r'scl:\s*([5-9]|1[0-9])', body_lower):
        contributions.append(("microsoft_marked_as_spam", 25))
    if re.search(r'sfv:\s*spm', body_lower):
        contributions.append(("spam_filter_verdict_spam", 25))
    if re.search(r'cat:\s*spm', body_lower):
        contributions.append(("categorized_as_spam", 20))
    if re.search(r'rf:\s*junkemail', body_lower):
        contributions.append(("delivered_to_junk_folder", 20))
    if re.search(r'x-forefront-antispam-report:.*spm', body_lower):
        contributions.append(("forefront_spam_detection", 15))
    
    spam_score_match = re.search(r'x-spam-score:\s*([\d.]+)', body_lower)
    if spam_score_match:
        spam_score = float(spam_score_match.group(1))
        if spam_score >= 5.0:
            contributions.append((f"spamassassin_score:{spam_score}", 30))
        elif spam_score >= 3.0:
            contributions.append((f"spamassassin_score:{spam_score}", 15))
            
    return contributions

# ========= Sender Name vs Email Mismatch Detection =========
def check_sender_name_email_mismatch(sender: str, body: str) -> List[Tuple[str, int]]:
    """
    Detect when sender name doesn't match email address (common in spam)
    Example: "John Smith <randomshop123@gmail.com>"
    """
    contributions = []

    # Extract display name if present
    name_match = re.search(r'^([^<]+)<([^>]+)>$', sender.strip())
    if not name_match:
        return []

    display_name = name_match.group(1).strip().lower()
    email_addr = name_match.group(2).strip().lower()
    sender_dom = _domain_of(email_addr)

    # Skip if no real display name
    if not display_name or '@' in display_name:
        return []

    # Check if name components are in email
    name_parts = re.findall(r'\w+', display_name)
    email_parts = re.findall(r'\w+', email_addr.split('@')[0])

    # Check for matches
    has_match = any(part in email_parts for part in name_parts if len(part) > 2)

    if not has_match and sender_dom in FREE_EMAIL_SENDERS:
        contributions.append(("sender_name_email_mismatch_free_provider", 8))
    elif not has_match:
        contributions.append(("sender_name_email_mismatch", 5))

    return contributions

# ==============================================================================
# 3-LAYER REPUTATION SCORING SYSTEM
# ==============================================================================

async def score_email_v3(
    sender: str,
    subject: str,
    body: str,
    urls: List[str],
    spf_result: str,
    dkim_result: str,
    dmarc_result: str,
    is_whitelisted: bool = False,
    recipient: str = "",
    display_name: str = ""
) -> Dict:
    """
    3-Layer reputation-based scoring:
    Layer A (Hard-bad): Blocklists, malicious URLs, auth failures → can dominate
    Layer B (Hard-good): Clean reputation → can neutralize soft signals
    Layer C (Soft/content): Keywords, formatting → capped at +25

    Conservative approach: Require multiple signals to block, avoid false positives.
    """
    score = 0
    reasons = []

    # ========== EARLY EXIT: INTERNAL EMAILS ==========
    # If sender and recipient are same domain (internal email), auto-safe
    sender_domain = sender.split('@')[-1] if '@' in sender else ""
    recipient_domain = recipient.split('@')[-1] if '@' in recipient else ""

    if sender_domain and recipient_domain and sender_domain == recipient_domain:
        print(f"   DEBUG: Internal email detected ({sender_domain}), auto-safe")
        return {
            "score": 0,
            "verdict": "safe",
            "category": "internal",
            "reasons": [("internal_email", 0)]
        }

    # ========== LAYER A: HARD-BAD (can dominate) ==========

    # Skip reputation checks for unknown/placeholder senders
    is_placeholder = sender == "unknown_sender_hidden@scan.system"

    # Check sender domain against Spamhaus DBL (DISABLED - causing false positives from Vercel IPs)
    # Spamhaus blocks queries from datacenter/cloud IPs, causing legitimate domains to be flagged
    # if sender_domain and not is_placeholder:
    #     is_dbl_listed = check_domain_spamhaus_dbl(sender_domain)
    #     print(f"   DEBUG: Spamhaus DBL check for {sender_domain}: {is_dbl_listed}")
    #     if is_dbl_listed:
    #         score += 70
    #         reasons.append(("spamhaus_dbl_listed", 70))
    is_dbl_listed = False  # Disabled for now

    # Check URLs against URLhaus (DISABLED - requires auth, getting 401)
    # urlhaus_hit = False
    # for url in urls[:5]:  # Check first 5 URLs
    #     if await check_url_urlhaus(url):
    #         urlhaus_hit = True
    #         break
    # if urlhaus_hit:
    #     score += 60
    #     reasons.append(("urlhaus_malicious", 60))
    urlhaus_hit = False  # Disabled for now

    # Check URLs against Safe Browsing
    has_malicious, malicious_urls = await check_urls_against_safe_browsing(urls)
    if has_malicious:
        score += 60
        reasons.append(("safe_browsing_malicious", 60))

    # Authentication failures
    spf_fail = spf_result.lower() not in ["pass", ""]
    dkim_fail = dkim_result.lower() not in ["pass", ""]
    dmarc_fail = dmarc_result.lower() not in ["pass", ""]

    if dmarc_fail and spf_fail:
        score += 35
        reasons.append(("dmarc_spf_fail", 35))
    elif dkim_fail and sender_domain:
        # Check if domain is new/unknown (simple heuristic: free email providers)
        if sender_domain in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]:
            score += 20
            reasons.append(("dkim_fail_new_domain", 20))

    # Early exit for hard-bad
    if score >= 75:
        return {
            "score": min(score, 100),
            "verdict": "block",
            "category": "malicious",
            "reasons": reasons
        }

    # ========== LAYER B: HARD-GOOD (dampeners & overrides) ==========

    spf_pass = spf_result.lower() == "pass"
    dkim_pass = dkim_result.lower() == "pass"
    dmarc_pass = dmarc_result.lower() == "pass"

    if spf_pass:
        score -= 8
        reasons.append(("spf_pass", -8))
    if dkim_pass:
        score -= 10
        reasons.append(("dkim_pass", -10))
    if dmarc_pass:
        score -= 10
        reasons.append(("dmarc_pass", -10))

    # Clean bill of health: all rep checks clean AND low content score → cap at 20
    # This protects legitimate transactional emails, but doesn't protect marketing
    # Skip for placeholder senders since we can't verify reputation
    # DISABLED - was causing marketing emails to bypass content scoring
    # if not is_placeholder:
    #     all_rep_clean = (not urlhaus_hit and not has_malicious and
    #                      not check_domain_spamhaus_dbl(sender_domain))
    #     if all_rep_clean and spf_pass and dkim_pass:
    #         score = min(score, 20)
    #         reasons.append(("clean_bill_of_health", 0))

    # Whitelist override → cap at 10
    if is_whitelisted:
        score = min(score, 10)
        reasons.append(("whitelisted_sender", 0))

    # ========== LAYER C: SOFT/CONTENT (marketing detection) ==========

    soft_score = 0
    combined = f"{subject} {body}".lower()

    # Unsubscribe detection (strong marketing signal) +20
    unsubscribe_patterns = ["unsubscribe", "opt out", "opt-out", "manage preferences",
                           "update email preferences", "email preferences"]
    if any(pattern in combined for pattern in unsubscribe_patterns):
        soft_score += 20
        reasons.append(("unsubscribe_link", 20))

    # "View in browser" pattern (marketing emails) +15
    view_browser_patterns = ["view this email in your browser", "view in browser",
                             "view online", "having trouble viewing"]
    if any(pattern in combined for pattern in view_browser_patterns):
        soft_score += 15
        reasons.append(("view_in_browser", 15))

    # Tracking URLs (utm parameters, marketing tracking) +12
    tracking_indicators = ["utm_source", "utm_campaign", "utm_medium", "utm_content",
                          "email_id", "track=", "tracking=", "campaign_id"]
    tracking_count = sum(1 for url in urls if any(t in url.lower() for t in tracking_indicators))
    if tracking_count >= 3:
        soft_score += 12
        reasons.append(("tracking_urls", 12))

    # Marketing language +15
    marketing_keywords = ["exclusive", "invite only", "limited time", "don't miss",
                         "before you go", "sign up now", "join now", "get started",
                         "claim your", "special offer", "act now"]
    marketing_hits = sum(1 for kw in marketing_keywords if kw in combined)
    if marketing_hits >= 2:
        marketing_score = min(marketing_hits * 5, 15)
        soft_score += marketing_score
        reasons.append(("marketing_language", marketing_score))

    # Urgency keywords +10
    urgency_keywords = ["urgent", "immediate", "expires", "deadline", "hurry",
                       "ending soon", "last chance", "final notice"]
    urgency_hits = sum(1 for kw in urgency_keywords if kw in combined)
    if urgency_hits > 0:
        urgency_score = min(urgency_hits * 5, 10)
        soft_score += urgency_score
        reasons.append(("urgency_language", urgency_score))

    # High link density (scaled by count) +8 to +20
    if len(urls) > 20:
        soft_score += 20
        reasons.append(("excessive_links", 20))
    elif len(urls) > 10:
        soft_score += 15
        reasons.append(("many_links", 15))
    elif len(urls) > 5:
        soft_score += 8
        reasons.append(("high_link_density", 8))

    # URL shorteners +8
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "ow.ly", "short.link"]
    has_shortener = any(s in url for url in urls for s in shorteners)
    if has_shortener:
        soft_score += 8
        reasons.append(("url_shortener", 8))

    # Suspicious TLDs (common in phishing) +25
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".biz.ua", ".ru.com",
                      ".click", ".loan", ".download", ".racing", ".top", ".work"]
    if sender_domain and any(sender_domain.endswith(tld) for tld in suspicious_tlds):
        soft_score += 25
        reasons.append(("suspicious_tld", 25))

    # Prize/scam language (phishing patterns) +25
    scam_keywords = ["congratulations", "you've been selected", "you won", "claim your free",
                    "free gift", "you've won", "winner", "claim now", "get your free",
                    "you have been chosen", "selected winner"]
    scam_hits = sum(1 for kw in scam_keywords if kw in combined)
    if scam_hits > 0:
        scam_score = min(scam_hits * 15, 25)
        soft_score += scam_score
        reasons.append(("scam_language", scam_score))

    # Survey/prize scam patterns +15
    survey_patterns = ["complete this survey", "take this survey", "answer these questions",
                      "short survey", "quick survey", "survey about"]
    if any(pattern in combined for pattern in survey_patterns):
        soft_score += 15
        reasons.append(("survey_scam", 15))

    # Romance/dating scam patterns +30
    romance_keywords = ["find love", "godly love", "christian singles", "meet singles",
                       "dating", "soulmate", "perfect match", "lonely", "companionship",
                       "romance", "relationship", "find your match"]
    romance_hits = sum(1 for kw in romance_keywords if kw in combined)
    if romance_hits > 0:
        romance_score = min(romance_hits * 15, 30)
        soft_score += romance_score
        reasons.append(("romance_scam", romance_score))

    # Hidden text obfuscation (soft hyphens, zero-width chars) +20
    obfuscation_indicators = ["\u00ad", "\u200b", "\u200c", "\u200d", "\ufeff"]  # soft hyphen, zero-width chars
    if any(char in subject + body for char in obfuscation_indicators):
        soft_score += 20
        reasons.append(("text_obfuscation", 20))

    # Display name domain mismatch (phishing tactic) +35
    # E.g., Display: "americanhomewarranty.net" but actual sender: "scammer@oeveward.com"
    if display_name and sender_domain:
        # Extract domain patterns from display name (look for domain-like strings)
        display_domains = re.findall(r'\b([a-zA-Z0-9-]+\.(?:com|net|org|edu|gov|co|io|ai|app))\b', display_name.lower())
        if display_domains:
            # Check if any display domain doesn't match actual sender domain
            if not any(d in sender_domain or sender_domain in d for d in display_domains):
                soft_score += 35
                reasons.append(("display_name_mismatch", 35))

    # Gibberish sender address (random characters) +30
    # E.g., "vjurmfjwaksdy@oeveward.com" - common in scam emails
    if sender and '@' in sender and sender != UNKNOWN_SENDER_PLACEHOLDER:
        username = sender.split('@')[0].lower()
        # Check for gibberish: long username (>10 chars) with low vowel ratio
        if len(username) > 10:
            vowels = sum(1 for c in username if c in 'aeiou')
            vowel_ratio = vowels / len(username)
            # Gibberish has very low vowel ratio (<0.25) or very high (>0.6)
            if vowel_ratio < 0.25 or vowel_ratio > 0.6:
                # Also check for repetitive patterns (additional signal)
                unique_chars = len(set(username))
                if unique_chars > 8:  # Truly random, not just "aaaaaaa"
                    soft_score += 30
                    reasons.append(("gibberish_sender", 30))

    # Cap soft/content at +80 (raised to catch phishing scams)
    soft_score = min(soft_score, 80)
    score += soft_score

    # Final bounds
    score = max(0, min(score, 100))

    # Determine verdict - Balanced thresholds
    # 0-34: Safe (transactional, legitimate)
    # 35-69: Caution (marketing, suspicious patterns)
    # 70+: Block (clear spam, multiple strong signals)
    if score >= 70:
        verdict = "block"
        category = "spam"
    elif score >= 35:
        verdict = "caution"
        category = "suspicious"
    else:
        verdict = "safe"
        category = "legitimate"

    return {
        "score": score,
        "verdict": verdict,
        "category": category,
        "reasons": reasons
    }

# ==============================================================================
# CATEGORIZATION ENGINE (Legacy - to be migrated)
# ==============================================================================

async def categorize_email(sender: str, subject: str, body: str, user_id: Optional[str] = None, force_neutral: bool = False) -> Dict:
    contributions = []
    flags = {}
    
    is_wl, wl_reason, is_bl, bl_reason = False, "", False, ""
    if user_id and not force_neutral:
        is_wl, wl_reason = check_whitelist(user_id, sender)
        is_bl, bl_reason = check_blocklist(user_id, sender)
        if is_wl: flags["whitelisted"] = True
        elif is_bl:
            return {"score": 100, "verdict": "block", "category": "blocked", "reasons": [bl_reason], "simple_reasons": [{"explanation": "Sender is Blocked", "severity": "high"}], "detailed_reasons": [{"explanation": "Sender is in your blocklist", "points": 100}], "blocked": True}

    sender_dom = sender.split('@')[-1].lower() if '@' in sender else ""
    combined = f"{subject} {body}".lower()
    urls = extract_urls(body)
    is_trusted_domain = any(t in sender_dom for t in TRUSTED_DOMAINS)
    
    if sender == UNKNOWN_SENDER_PLACEHOLDER:
        contributions.append(("unverified_sender_source", 5))
        
    if not is_trusted_domain or force_neutral:
        bayesian_score = calculate_bayesian_score(combined)
        if bayesian_score > 5: contributions.append(("bayesian_spam_content", bayesian_score))
        elif bayesian_score < -2 and not force_neutral: contributions.append(("bayesian_ham_bonus", bayesian_score))
            
    tracking_hit, bad_tld_hit, long_query_hit, shortener_urls = _url_features(urls)
    has_malicious, malicious_urls = await check_urls_against_safe_browsing(urls)
    
    if has_malicious: contributions.append(("malicious_url_detected", 100))
    if tracking_hit: contributions.append(("tracking_urls_detected", 10))
    if bad_tld_hit: contributions.append(("suspicious_tld_detected", 20))
    if long_query_hit: contributions.append(("long_query_string_urls", 10))
    if shortener_urls: contributions.append(("url_shorteners_detected", 15))
    
    if len(urls) > 5: contributions.append(("high_link_density", 15))
        
    header_contribs = analyze_email_headers(body)
    if header_contribs: contributions.extend(header_contribs)
        
    if _is_all_caps(subject): contributions.append(("all_caps_subject", 10))
    if re.search(r'\b(urgent|verify|action)\b', subject.lower()): contributions.append(("urgency_pressure", 15))
        
    mismatch_contribs = check_sender_name_email_mismatch(sender, body)
    if mismatch_contribs: contributions.extend(mismatch_contribs)
        
    phishing_matches = sum(1 for p in PHISHING_WORDS if re.search(p, combined))
    if phishing_matches >= 2: contributions.append(("phishing_language", 40))
    elif phishing_matches == 1: contributions.append(("potential_phishing_language", 15))
        
    biz_score = 0
    for pattern, weight in BUSINESS_SPAM_WEIGHTS.items():
        if re.search(pattern, combined): biz_score += weight
    is_free_email = sender_dom in FREE_EMAIL_SENDERS
    if biz_score >= 20: contributions.append(("business_spam", biz_score))
    elif biz_score >= 10: contributions.append(("business_spam", biz_score))
    if is_free_email and biz_score > 0: contributions.append(("free_email_business_content", 20))
        
    marketing_contribs = detect_marketing_email(body, subject)
    if marketing_contribs: contributions.extend(marketing_contribs)
        
    score = sum(c[1] for c in contributions)
    
    spam_signals = [c for c in contributions if c[1] > 0]
    if is_trusted_domain and not force_neutral:
        if not spam_signals:
            score = max(0, score - 15)
            contributions.append(("trusted_domain_bonus", -15))
        elif score < 20:
            score = max(0, score - 10)
            contributions.append(("trusted_domain_bonus", -10))
            
    if is_wl and not force_neutral:
        if score < 70:
            score = max(0, score - 50)
            contributions.append((wl_reason, -50))
        else:
            contributions.append((f"{wl_reason} (IGNORED - High Risk)", 0))
            
    score = max(0, min(100, score))
    
    has_marketing = any("marketing" in c[0] for c in spam_signals)
    has_biz = any("business" in c[0] for c in spam_signals)
    
    if score >= MIN_BLOCK_SCORE:
        verdict = "block"
        if any("phish" in c[0] for c in spam_signals): category = "phishing"
        elif has_marketing: category = "marketing"
        elif has_biz: category = "business_spam"
        else: category = "suspicious"
    elif score >= 10 or has_marketing:
        verdict = "caution"
        category = "marketing" if has_marketing else "suspicious"
    else:
        verdict = "safe"
        category = "legitimate"
        
    simple_reasons = [{"explanation": get_simple_explanation(r[0]), "severity": "high" if r[1] > 20 else "medium"} for r in contributions if r[1] > 0]
    detailed_reasons = [{"explanation": get_simple_explanation(r[0]), "points": int(r[1])} for r in contributions if r[1] != 0]
    
    return {
        "score": score, "verdict": verdict, "category": category,
        "simple_reasons": simple_reasons, "detailed_reasons": detailed_reasons,
        "whitelisted": is_wl, "blocked": False, "urls_found": urls
    }

# ==============================================================================
# REPORT GENERATION
# ==============================================================================

def build_html_report(sender: str, subject: str, result: Dict, original_sender: str | None, evaluated_sender: str) -> str:
    """
    Simplified plain-text-like HTML report for better email deliverability.
    Minimal styling to avoid spam filters.
    """
    if result['verdict'] == 'block':
        icon, title = "🚫", "BLOCK - Spam"
    elif result['verdict'] == 'caution':
        icon, title = "⚠️", "CAUTION - Suspicious"
    else:
        icon, title = "✅", "SAFE - Legitimate"

    display_sender = evaluated_sender
    if evaluated_sender == UNKNOWN_SENDER_PLACEHOLDER:
        display_sender = "Undisclosed / Hidden Sender"

    # Build breakdown list (simple text)
    breakdown_lines = ""
    for r in result['detailed_reasons']:
        pts = r['points']
        sign = "+" if pts > 0 else ""
        breakdown_lines += f"  • {html.escape(r['explanation'])}: {sign}{pts}\n"

    if not breakdown_lines:
        breakdown_lines = "  • No specific flags detected.\n"

    # Build analysis list
    analysis_lines = ""
    if result['simple_reasons']:
        for r in result['simple_reasons']:
            analysis_lines += f"  • {html.escape(r['explanation'])}\n"
    else:
        analysis_lines = "  • Email appears safe.\n"

    # Simple plain-text-like HTML (minimal styling for deliverability)
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 20px auto; padding: 20px; background: #ffffff;">

<div style="text-align: center; padding: 20px 0; border-bottom: 2px solid #e0e0e0;">
  <div style="font-size: 48px;">{icon}</div>
  <h1 style="margin: 10px 0; font-size: 24px;">{title}</h1>
  <p style="font-size: 18px; font-weight: bold;">Spam Score: {result['score']}/100</p>
</div>

<div style="padding: 20px 0;">
  <p><strong>Subject:</strong> {html.escape(subject)}</p>
  <p><strong>Sender:</strong> {html.escape(display_sender)}</p>
  {f'<p><strong>Forwarded From:</strong> {html.escape(original_sender)}</p>' if original_sender else ''}
</div>

<div style="padding: 20px 0; border-top: 1px solid #e0e0e0;">
  <h2 style="font-size: 16px; margin-bottom: 10px;">📊 Scoring Breakdown</h2>
  <pre style="font-family: monospace; font-size: 13px; line-height: 1.6; background: #f5f5f5; padding: 15px; border-radius: 4px; overflow-x: auto;">{breakdown_lines}</pre>
</div>

<div style="padding: 20px 0; border-top: 1px solid #e0e0e0;">
  <h2 style="font-size: 16px; margin-bottom: 10px;">🛡️ Analysis</h2>
  <pre style="font-family: monospace; font-size: 13px; line-height: 1.6; background: #f5f5f5; padding: 15px; border-radius: 4px; overflow-x: auto;">{analysis_lines}</pre>
</div>

<div style="padding: 20px 0; border-top: 1px solid #e0e0e0; text-align: center; font-size: 12px; color: #666;">
  <p>Analysis provided by SpamScore</p>
  <p><a href="https://spamscore-dashboard.vercel.app" style="color: #0066cc;">Manage your settings</a></p>
</div>

</body>
</html>"""

def build_text_report(sender: str, subject: str, result: Dict, original_sender: str | None, evaluated_sender: str) -> str:
    return f"VERDICT: {result['verdict'].upper()}\nSCORE: {result['score']}\nSENDER: {evaluated_sender}\n\nSCORING BREAKDOWN:\n" + "\n".join([f"- {r['explanation']}: {r['points']}" for r in result['detailed_reasons']])

# ==============================================================================
# WEBHOOK RECEIVER
# ==============================================================================

@app.post("/receive")
async def receive_mailgun_webhook(request: Request):
    """
    Main webhook for receiving emails from Mailgun
    Fixed to properly capture body fields with multiple name variations
    """
    # Get ALL form data
    form_data = await request.form()
    form_dict = dict(form_data)

    # Extract required fields with fallbacks
    sender = form_dict.get("sender") or form_dict.get("from") or form_dict.get("From") or ""
    recipient = form_dict.get("recipient") or form_dict.get("to") or form_dict.get("To") or ""
    subject = form_dict.get("subject") or form_dict.get("Subject") or ""

    # Try ALL possible body field name variations (Mailgun uses hyphens!)
    body_plain = (
        form_dict.get("body-plain") or    # Mailgun sends THIS
        form_dict.get("body_plain") or
        form_dict.get("bodyPlain") or
        form_dict.get("body") or
        form_dict.get("text") or
        ""
    )

    body_html = (
        form_dict.get("body-html") or     # Mailgun sends THIS
        form_dict.get("body_html") or
        form_dict.get("bodyHtml") or
        form_dict.get("html") or
        ""
    )

    stripped_text = (
        form_dict.get("stripped-text") or  # Mailgun sends THIS
        form_dict.get("stripped_text") or
        form_dict.get("strippedText") or
        ""
    )

    # Auth headers (try both formats)
    X_Mailgun_Spf = form_dict.get("X-Mailgun-Spf") or form_dict.get("X_Mailgun_Spf") or ""
    X_Mailgun_Dkim_Check_Result = form_dict.get("X-Mailgun-Dkim-Check-Result") or form_dict.get("X_Mailgun_Dkim_Check_Result") or ""
    dmarc = form_dict.get("dmarc") or form_dict.get("DMARC") or ""
    From = form_dict.get("From") or form_dict.get("from") or sender

    # Storage URLs
    message_url = form_dict.get("message-url") or form_dict.get("message_url") or ""
    storage_url = form_dict.get("storage-url") or form_dict.get("storage_url") or ""

    user_email = sender.lower().strip()
    user_id = get_user_id_from_email(user_email)

    # FIX: Use body_html for detection when body_plain is empty
    # stripped_text removes forwarded headers, so skip it for detection
    body_struct = body_plain or body_html or stripped_text
    body_content = body_html or body_plain or stripped_text
    
    # DEBUG: Log ALL form parameters Mailgun is sending
    all_keys = list(form_dict.keys())
    print(f"   DEBUG: ALL Mailgun parameters received: {all_keys}")
    print(f"   DEBUG: message_url=[{message_url}], storage_url=[{storage_url}]")

    print(f"Processing: {sender} | {subject}")
    print(f"   DEBUG: Auth headers - SPF=[{X_Mailgun_Spf}], DKIM=[{X_Mailgun_Dkim_Check_Result}], DMARC=[{dmarc}], From=[{From}]")

    # DEBUG: Log body structure for forwarded email debugging
    if "fwd" in subject.lower() or "fw:" in subject.lower():
        print(f"   DEBUG: Forward detected in subject")
        print(f"   DEBUG: body_plain length: {len(body_plain) if body_plain else 0}")
        print(f"   DEBUG: body_html length: {len(body_html) if body_html else 0}")
        print(f"   DEBUG: stripped_text length: {len(stripped_text) if stripped_text else 0}")
        print(f"   DEBUG: body_struct source: {'body_plain' if body_plain else ('body_html' if body_html else 'stripped_text')}")
        print(f"   DEBUG: body_struct first 500 chars:\n{body_struct[:500]}")

    # 1. Detect Original Sender
    original_sender_result = detect_forwarded_original_sender(body_struct)
    original_sender = original_sender_result[0] if original_sender_result else None
    original_display_name = original_sender_result[1] if original_sender_result else ""

    # 2. Check if Forward
    is_forward = re.search(r'^(fwd?|fw):', subject, re.I) or "forwarded message" in body_struct.lower()

    # 3. Evaluation Logic
    if original_sender:
        eval_sender = original_sender
        use_uid = None
        force_neutral = True
        print(f"   -> Found Original Sender: {eval_sender} (Display: {original_display_name})")
        
    elif is_forward:
        # Fallback: Forwarded but no sender found
        eval_sender = UNKNOWN_SENDER_PLACEHOLDER
        use_uid = None
        force_neutral = True
        print("   -> Forward detected, sender unknown. Using Strict Mode.")
        
    else:
        # Direct Scan
        eval_sender = sender
        use_uid = user_id
        force_neutral = False
        print(f"   -> Direct Scan: {eval_sender}")
        
    # 4. Extract URLs and check whitelist for V3 scoring
    try:
        urls = extract_urls(body_content) if body_content else []
    except Exception as e:
        print(f"   ERROR: Failed to extract URLs: {e}")
        urls = []

    # Check if sender is whitelisted
    is_whitelisted = False
    try:
        if use_uid:
            sender_dom = eval_sender.split('@')[-1] if '@' in eval_sender else ""
            wl_emails = redis_client.smembers(f"user:{use_uid}:whitelist:email") if redis_client else set()
            wl_domains = redis_client.smembers(f"user:{use_uid}:whitelist:domain") if redis_client else set()
            is_whitelisted = (eval_sender.encode() in wl_emails or
                             sender_dom.encode() in wl_domains)
    except Exception as e:
        print(f"   ERROR: Failed to check whitelist: {e}")
        is_whitelisted = False

    # 5. Run V3 Analysis (reputation-based 3-layer scoring)
    print(f"   -> Running V3 scoring with {len(urls)} URLs, SPF={X_Mailgun_Spf}, DKIM={X_Mailgun_Dkim_Check_Result}, DMARC={dmarc}")
    try:
        result = await score_email_v3(
            sender=eval_sender,
            subject=subject,
            body=body_content or "",
            urls=urls,
            spf_result=X_Mailgun_Spf,
            dkim_result=X_Mailgun_Dkim_Check_Result,
            dmarc_result=dmarc,
            is_whitelisted=is_whitelisted,
            recipient=recipient,
            display_name=original_display_name
        )
        print(f"   -> V3 Score: {result['score']}/100, Verdict: {result['verdict']}, Reasons: {len(result.get('reasons', []))}")
    except Exception as e:
        print(f"   ERROR: V3 scoring failed: {e}")
        import traceback
        traceback.print_exc()
        # Fallback to safe verdict with minimal score
        result = {
            "score": 5,
            "verdict": "safe",
            "category": "unknown",
            "reasons": [("scoring_error", 5)]
        }

    # Add legacy fields for compatibility with report generation
    result["whitelisted"] = is_whitelisted
    result["blocklisted"] = False

    # Convert v3 reasons format to legacy format for report generation
    # V3 format: [("spamhaus_dbl_listed", 70), ("spf_pass", -8)]
    # Legacy format: [{"explanation": "Spamhaus DBL Listed", "points": 70}]
    reason_labels = {
        "spamhaus_dbl_listed": "Spamhaus DBL Listed",
        "urlhaus_malicious": "URLhaus Malicious URL",
        "safe_browsing_malicious": "Google Safe Browsing Malicious",
        "dmarc_spf_fail": "DMARC + SPF Authentication Failure",
        "dkim_fail_new_domain": "DKIM Failure (New Domain)",
        "spf_pass": "SPF Authentication Pass",
        "dkim_pass": "DKIM Authentication Pass",
        "dmarc_pass": "DMARC Authentication Pass",
        "clean_bill_of_health": "Clean Reputation (All Checks Pass)",
        "whitelisted_sender": "Whitelisted Sender",
        "internal_email": "Internal Email (Same Domain)",
        "unsubscribe_link": "Unsubscribe Link Detected (Marketing)",
        "view_in_browser": "View in Browser Link (Marketing)",
        "tracking_urls": "Tracking URLs Detected (Marketing)",
        "marketing_language": "Marketing Language Detected",
        "urgency_language": "Urgency Language Detected",
        "excessive_links": "Excessive Links (20+)",
        "many_links": "Many Links (10+)",
        "high_link_density": "High Link Density (5+)",
        "url_shortener": "URL Shortener Detected",
        "suspicious_tld": "Suspicious Domain Extension (Phishing)",
        "scam_language": "Prize/Scam Language Detected",
        "survey_scam": "Survey Scam Pattern Detected",
        "romance_scam": "Romance/Dating Scam Pattern Detected",
        "text_obfuscation": "Hidden Text Obfuscation Detected",
        "display_name_mismatch": "Display Name Domain Mismatch (Phishing)",
        "gibberish_sender": "Gibberish Sender Address (Scam)"
    }

    result["detailed_reasons"] = [
        {"explanation": reason_labels.get(key, key.replace("_", " ").title()),
         "points": points}
        for key, points in result.get("reasons", [])
    ]

    # Add simple_reasons for legacy compatibility (with severity for report)
    result["simple_reasons"] = [
        {
            "explanation": reason_labels.get(key, key.replace("_", " ").title()),
            "severity": "high" if points >= 30 else "medium"
        }
        for key, points in result.get("reasons", [])
        if points > 0  # Only include positive contributions
    ]
    
    # 5. Record & Report
    scan_id = hashlib.sha256(f"{user_id}{eval_sender}{subject}{datetime.now()}".encode()).hexdigest()[:16]
    
    record_scan(
        user_id, scan_id, eval_sender, subject, 
        result["score"], result["verdict"], result["category"], 
        result["whitelisted"], False
    )
    
    html_report = build_html_report(sender, subject, result, original_sender, eval_sender)
    text_report = build_text_report(sender, subject, result, original_sender, eval_sender)
    
    title_emoji = "🚫" if result['verdict'] == 'block' else "⚠️" if result['verdict'] == 'caution' else "✅"
    title = f"{title_emoji} SpamScore: {result['verdict'].upper()} ({result['score']}/100)"
    
    await send_report_via_mailgun(sender, title, html_report, text_report)
    
    return {"status": "ok", "verdict": result["verdict"], "score": result["score"]}

async def send_report_via_mailgun(to, subj, html, text):
    if not (MG_KEY and MG_DOMAIN): return
    async with httpx.AsyncClient() as client:
        await client.post(
            f"https://api.mailgun.net/v3/{MG_DOMAIN}/messages",
            auth=("api", MG_KEY),
            data={"from": REPLY_FROM, "to": to, "subject": subj, "html": html, "text": text}
        )

# ==============================================================================
# DASHBOARD API ENDPOINTS
# ==============================================================================

@app.get("/api/whitelist/list")
async def api_get_whitelist(user_email: str):
    if not redis_client: raise HTTPException(503, "DB Error")
    user_id = get_user_id_from_email(user_email)
    wl = []
    for t in ['email', 'domain']:
        for v in get_whitelist(user_id, t):
            meta = redis_client.hgetall(f"whitelist:{user_id}:{t}:meta:{v}")
            wl.append({"type": t, "value": v, "added_at": meta.get("added_at", "")})
    return {"whitelist": wl}

@app.post("/api/whitelist/add")
async def api_add_to_whitelist(req: WhitelistAddRequest):
    if not redis_client: raise HTTPException(503, "DB Error")
    uid = get_user_id_from_email(req.user_email)
    add_to_whitelist(uid, req.value, req.type)
    return {"success": True}

@app.post("/api/whitelist/remove")
async def api_rem_from_whitelist(req: WhitelistRemoveRequest):
    if not redis_client: raise HTTPException(503, "DB Error")
    uid = get_user_id_from_email(req.user_email)
    remove_from_whitelist(uid, req.value, req.type)
    return {"success": True}

@app.get("/api/blocklist/list")
async def api_get_blocklist(user_email: str):
    if not redis_client: raise HTTPException(503, "DB Error")
    user_id = get_user_id_from_email(user_email)
    bl = []
    for t in ['email', 'domain']:
        for v in redis_client.smembers(get_blocklist_key(user_id, t)):
            meta = redis_client.hgetall(f"blocklist:{user_id}:{t}:meta:{v}")
            bl.append({"type": t, "value": v, "added_at": meta.get("added_at", "")})
    return {"blocklist": bl}

@app.post("/api/blocklist/add")
async def api_add_to_blocklist(req: BlocklistAddRequest):
    if not redis_client: raise HTTPException(503, "DB Error")
    uid = get_user_id_from_email(req.user_email)
    if is_whitelisted(uid, req.value, req.type): 
        remove_from_whitelist(uid, req.value, req.type)
    add_to_blocklist(uid, req.value, req.type)
    return {"success": True}

@app.post("/api/blocklist/remove")
async def api_rem_from_blocklist(req: BlocklistRemoveRequest):
    if not redis_client: raise HTTPException(503, "DB Error")
    uid = get_user_id_from_email(req.user_email)
    remove_from_blocklist(uid, req.value, req.type)
    return {"success": True}

@app.get("/api/history")
async def api_get_history_endpoint(user_email: str, limit: int = 50):
    if not redis_client: raise HTTPException(503, "DB Error")
    return {"history": get_scan_history(get_user_id_from_email(user_email), limit)}

@app.get("/api/stats/summary")
async def api_get_stats_summary(user_email: str):
    if not redis_client: raise HTTPException(503, "DB Error")
    uid = get_user_id_from_email(user_email)
    return {
        "monthly_usage": get_monthly_scan_count(uid),
        "monthly_limit": 100
    }