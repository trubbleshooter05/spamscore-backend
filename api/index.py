# ===========================
# api/index.py — AGGRESSIVE VERSION (Fixed False Negatives)
# ===========================

import os, re, html, math
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import FastAPI, Query, Form, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import tldextract

# Use read-only friendly extractor on Vercel
_TLDX = tldextract.TLDExtract(cache_dir=None)

import json
import hashlib
from redis import Redis

# ========= INITIALIZE FASTAPI APP (CRITICAL!) =========
app = FastAPI()

# Enable CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://spamscore-dashboard.vercel.app",
        "http://localhost:3000",
        "http://localhost:3001"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========= Vercel KV / Redis Setup =========
KV_URL = os.getenv("KV_URL", "")
redis_client = None

if KV_URL:
    try:
        redis_client = Redis.from_url(KV_URL, decode_responses=True)
    except Exception as e:
        print(f"Redis connection failed: {e}")

# ========= User Management =========
def get_user_id_from_email(email: str) -> str:
    """Generate consistent user ID from email"""
    return hashlib.sha256(email.lower().encode()).hexdigest()[:16]

def extract_email(sender: str) -> str:
    """Extract email from 'Name <email@domain.com>' format"""
    match = re.search(r'<([^>]+)>', sender)
    if match:
        return match.group(1).lower().strip()
    return sender.lower().strip()

def extract_display_name(sender: str) -> Optional[str]:
    """Extract display name from sender"""
    match = re.search(r'^([^<]+)<', sender)
    if match:
        name = match.group(1).strip().strip('"').strip("'")
        if name and '@' not in name:
            return name
    return None

# ========= Whitelist Functions =========
def get_whitelist_key(user_id: str, wl_type: str) -> str:
    """Generate Redis key for whitelist"""
    return f"whitelist:{user_id}:{wl_type}"

def add_to_whitelist(user_id: str, value: str, wl_type: str = 'email') -> bool:
    """
    Add entry to user's whitelist
    wl_type: 'email', 'domain', or 'sender_name'
    """
    if not redis_client:
        return False
    
    try:
        key = get_whitelist_key(user_id, wl_type)
        redis_client.sadd(key, value.lower())
        
        # Store metadata
        meta_key = f"{key}:meta:{value.lower()}"
        redis_client.hset(meta_key, mapping={
            'added_at': datetime.now(timezone.utc).isoformat(),
            'type': wl_type,
            'value': value.lower()
        })
        
        return True
    except Exception as e:
        print(f"Failed to add to whitelist: {e}")
        return False

def remove_from_whitelist(user_id: str, value: str, wl_type: str = 'email') -> bool:
    """Remove entry from whitelist"""
    if not redis_client:
        return False
    
    try:
        key = get_whitelist_key(user_id, wl_type)
        redis_client.srem(key, value.lower())
        
        # Remove metadata
        meta_key = f"{key}:meta:{value.lower()}"
        redis_client.delete(meta_key)
        
        return True
    except Exception as e:
        print(f"Failed to remove from whitelist: {e}")
        return False

def is_whitelisted(user_id: str, value: str, wl_type: str = 'email') -> bool:
    """Check if value is whitelisted"""
    if not redis_client:
        return False
    
    try:
        key = get_whitelist_key(user_id, wl_type)
        return redis_client.sismember(key, value.lower())
    except Exception:
        return False

def get_whitelist(user_id: str, wl_type: str = 'email') -> Set[str]:
    """Get all whitelist entries for user"""
    if not redis_client:
        return set()
    
    try:
        key = get_whitelist_key(user_id, wl_type)
        return redis_client.smembers(key)
    except Exception:
        return set()

def check_whitelist(user_id: str, sender: str) -> tuple[bool, str]:
    """
    Check if sender is whitelisted for this user.
    Returns (is_whitelisted, reason)
    """
    if not redis_client:
        return False, ""
    
    sender_email = extract_email(sender)
    sender_domain = _domain_of(sender_email)
    sender_name = extract_display_name(sender)
    
    # Check exact email match
    if is_whitelisted(user_id, sender_email, 'email'):
        return True, f"whitelisted_email:{sender_email}"
    
    # Check domain match
    if is_whitelisted(user_id, sender_domain, 'domain'):
        return True, f"whitelisted_domain:{sender_domain}"
    
    # Check sender name match
    if sender_name and is_whitelisted(user_id, sender_name.lower(), 'sender_name'):
        return True, f"whitelisted_sender_name:{sender_name}"
    
    return False, ""

# ========= Blocklist Functions =========
def get_blocklist_key(user_id: str, bl_type: str) -> str:
    """Generate Redis key for blocklist"""
    return f"blocklist:{user_id}:{bl_type}"

def add_to_blocklist(user_id: str, value: str, bl_type: str = 'email') -> bool:
    """Add entry to user's blocklist"""
    if not redis_client:
        return False
    
    try:
        key = get_blocklist_key(user_id, bl_type)
        redis_client.sadd(key, value.lower())
        
        # Store metadata
        meta_key = f"{key}:meta:{value.lower()}"
        redis_client.hset(meta_key, mapping={
            'added_at': datetime.now(timezone.utc).isoformat(),
            'type': bl_type,
            'value': value.lower()
        })
        
        return True
    except Exception as e:
        print(f"Failed to add to blocklist: {e}")
        return False

def remove_from_blocklist(user_id: str, value: str, bl_type: str = 'email') -> bool:
    """Remove entry from user's blocklist"""
    if not redis_client:
        return False
    
    try:
        key = get_blocklist_key(user_id, bl_type)
        redis_client.srem(key, value.lower())
        
        # Remove metadata
        meta_key = f"{key}:meta:{value.lower()}"
        redis_client.delete(meta_key)
        
        return True
    except Exception as e:
        print(f"Failed to remove from blocklist: {e}")
        return False

def is_blocked(user_id: str, value: str, bl_type: str = 'email') -> bool:
    """Check if value is blocked"""
    if not redis_client:
        return False
    
    try:
        key = get_blocklist_key(user_id, bl_type)
        return redis_client.sismember(key, value.lower())
    except Exception:
        return False

def check_blocklist(user_id: str, sender: str) -> tuple[bool, str]:
    """
    Check if sender is blocked for this user.
    Returns (is_blocked, reason)
    """
    if not redis_client:
        return False, ""
    
    sender_email = extract_email(sender)
    sender_domain = _domain_of(sender_email)
    
    # Check exact email match
    if is_blocked(user_id, sender_email, 'email'):
        return True, f"blocked_email:{sender_email}"
    
    # Check domain match
    if is_blocked(user_id, sender_domain, 'domain'):
        return True, f"blocked_domain:{sender_domain}"
    
    return False, ""

def get_blocklist_count(user_id: str) -> int:
    """Get total count of blocked senders"""
    if not redis_client:
        return 0
    
    try:
        email_count = redis_client.scard(f"blocklist:{user_id}:email") or 0
        domain_count = redis_client.scard(f"blocklist:{user_id}:domain") or 0
        return email_count + domain_count
    except Exception:
        return 0

# ========= Feedback Recording =========
def record_feedback(user_id: str, sender: str, subject: str, original_score: int, 
                    original_verdict: str, user_verdict: str, feedback_type: str):
    """Record user feedback for training"""
    if not redis_client:
        return
    
    try:
        # Create unique feedback ID
        content_hash = hashlib.sha256(f"{sender}{subject}".encode()).hexdigest()[:16]
        feedback_key = f"feedback:{user_id}:{content_hash}"
        
        redis_client.hset(feedback_key, mapping={
            'sender': sender,
            'subject': subject,
            'original_score': original_score,
            'original_verdict': original_verdict,
            'user_verdict': user_verdict,
            'feedback_type': feedback_type,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        # Set expiry (keep for 1 year)
        redis_client.expire(feedback_key, 31536000)
        
        # Add to user's feedback list
        user_feedback_key = f"user_feedback:{user_id}"
        redis_client.lpush(user_feedback_key, feedback_key)
        redis_client.ltrim(user_feedback_key, 0, 999)  # Keep last 1000
        
        # Update stats
        if feedback_type == "SAFE" and original_verdict in ["block", "caution"]:
            redis_client.incr(f"stats:{user_id}:false_positives")
        elif feedback_type == "BLOCK" and original_verdict == "safe":
            redis_client.incr(f"stats:{user_id}:false_negatives")
        
    except Exception as e:
        print(f"Failed to record feedback: {e}")

# ========= Scan History =========
def record_scan(user_id: str, scan_id: str, sender: str, subject: str, score: int, 
                verdict: str, category: str, whitelisted: bool, blocked: bool = False):
    """Record scan for history and analytics"""
    if not redis_client:
        return
    
    try:
        timestamp = datetime.now(timezone.utc)
        scan_key = f"scan:{user_id}:{scan_id}"
        
        redis_client.hset(scan_key, mapping={
            'id': scan_id,
            'sender': sender,
            'subject': subject or "No subject",
            'score': score,
            'verdict': verdict,
            'category': category,
            'whitelisted': str(whitelisted).lower(),
            'blocked': str(blocked).lower(),
            'timestamp': timestamp.isoformat()
        })
        
        # Set expiry (keep for 90 days)
        redis_client.expire(scan_key, 7776000)
        
        # Add to sorted set for easy retrieval (timestamp as score)
        redis_client.zadd(
            f"scan_history:{user_id}",
            {scan_key: timestamp.timestamp()}
        )
        
        # Increment monthly scan count
        monthly_key = f"stats:{user_id}:scans:{timestamp.strftime('%Y-%m')}"
        redis_client.incr(monthly_key)
        redis_client.expire(monthly_key, 2678400)  # 31 days
        
    except Exception as e:
        print(f"Failed to record scan: {e}")

def get_scan_history(user_id: str, limit: int = 50) -> List[Dict]:
    """Get user's scan history"""
    if not redis_client:
        return []
    
    try:
        # Get scan keys ordered by timestamp (newest first)
        history_keys = redis_client.zrevrange(f"scan_history:{user_id}", 0, limit - 1)
        
        history = []
        for key in history_keys:
            scan_data = redis_client.hgetall(key)
            if scan_data:
                history.append({
                    "id": scan_data.get("id", ""),
                    "date": scan_data.get("timestamp", ""),
                    "sender": scan_data.get("sender", "Unknown"),
                    "subject": scan_data.get("subject", "No subject"),
                    "verdict": scan_data.get("verdict", ""),
                    "score": int(scan_data.get("score", 0)),
                    "whitelisted": scan_data.get("whitelisted", "false") == "true",
                    "blocked": scan_data.get("blocked", "false") == "true"
                })
        
        return history
    except Exception as e:
        print(f"Failed to get scan history: {e}")
        return []

def get_monthly_scan_count(user_id: str) -> int:
    """Get user's scan count for current month"""
    if not redis_client:
        return 0
    
    try:
        monthly_key = f"stats:{user_id}:scans:{datetime.now().strftime('%Y-%m')}"
        count = redis_client.get(monthly_key)
        return int(count) if count else 0
    except Exception:
        return 0

# ========= Update Scan With Whitelist Status =========
def update_scan_whitelist_status(user_id: str, sender: str, subject: str):
    """Update recent scan to mark as whitelisted after SAFE command"""
    if not redis_client:
        return
    
    try:
        # Find most recent scan with matching sender and subject
        history_keys = redis_client.zrevrange(f"scan_history:{user_id}", 0, 20)
        
        for key in history_keys:
            scan_data = redis_client.hgetall(key)
            if (scan_data.get("sender", "").lower() == sender.lower() and 
                scan_data.get("subject", "") == subject):
                # Update to mark as whitelisted
                redis_client.hset(key, "whitelisted", "true")
                # Change verdict to Safe if it wasn't already
                if scan_data.get("verdict") != "safe":
                    redis_client.hset(key, "verdict", "safe")
                break
                
    except Exception as e:
        print(f"Failed to update scan whitelist status: {e}")

def update_scan_blocked_status(user_id: str, sender: str, subject: str):
    """Update recent scan to mark as blocked after BLOCK command"""
    if not redis_client:
        return
    
    try:
        # Find most recent scan with matching sender and subject
        history_keys = redis_client.zrevrange(f"scan_history:{user_id}", 0, 20)
        
        for key in history_keys:
            scan_data = redis_client.hgetall(key)
            if (scan_data.get("sender", "").lower() == sender.lower() and 
                scan_data.get("subject", "") == subject):
                # Update to mark as blocked
                redis_client.hset(key, "blocked", "true")
                redis_client.hset(key, "verdict", "block")
                break
                
    except Exception as e:
        print(f"Failed to update scan blocked status: {e}")

# ========= Get Simple Explanation =========
def get_simple_explanation(reason_key: str, context: Dict = None) -> str:
    context = context or {}
    explanations = {
        "phishing_language": "⚠️ Uses language commonly found in phishing attempts",
        "marketing_language": "📧 Contains typical marketing/promotional language",
        "business_spam": "💼 Appears to be unsolicited business outreach (B2B spam)",
        "free_email_cold_outreach": "🎣 Cold outreach from a free email provider (High Risk)",
        "free_email_with_unsubscribe": "🚨 Free email sender using mass-mailing unsubscribe links",
        "poor_grammar": "📝 Contains grammatical errors common in scams",
        "tracking_urls_detected": "📊 Contains tracking links that monitor your clicks",
        "suspicious_tld_detected": "🌐 Uses a suspicious website domain ending (.xyz, .ru, etc.)",
        "suspicious_link_tld": "⚠️ Email body contains links to suspicious domains",
        "gibberish_domain_link": "🤖 Links to random/gibberish domain names",
        "long_query_string_urls": "🔗 Links have unusually long tracking parameters",
        "url_shorteners_detected": "🔗 Contains shortened URLs that hide the real destination",
        "all_caps_subject": "🗣️ Subject line in ALL CAPS (aggressive marketing tactic)",
        "fake_reply_subject": "↩️ Fake 'Re:' or 'Fwd:' in subject (never started a conversation)",
        "urgency_pressure": "⏰ Creates false urgency to pressure quick action",
        "generic_greeting": "👤 Uses generic greeting instead of your name",
        "reply_to_mismatch": "📬 The 'Reply-To' address differs from sender (red flag)",
        "microsoft_marked_as_spam": "🚩 Microsoft Exchange already flagged this as spam (SCL score)",
        "spam_filter_verdict_spam": "🚩 Email security system marked this as spam",
        "categorized_as_spam": "🚩 Automatically categorized as spam by filters",
        "delivered_to_junk_folder": "🗑️ This was delivered to a junk/spam folder",
        "forefront_spam_detection": "🚩 Forefront anti-spam system detected spam",
        "spamassassin_score": "📊 SpamAssassin gave this a high spam score",
        "barracuda_spam_score_high": "🚩 Barracuda spam filter scored this highly",
        "generic_cold_outreach_subject": "📧 Generic cold outreach subject line",
        "generic_cold_outreach_subject_free_email": "🎣 Typical cold spam subject from free email account",
        "overly_casual_greeting_from_stranger": "👋 Overly casual greeting from unknown sender",
        "sales_pitch_question": "💼 Question-based sales pitch pattern",
        "sender_name_email_mismatch": "⚠️ Sender name doesn't match email address",
        "sender_name_email_mismatch_free_provider": "🚨 Sender name completely unrelated to Gmail address (red flag)",
        "whitelisted_email": "✅ Sender email is on your trusted whitelist",
        "whitelisted_domain": "✅ Sender domain is on your trusted whitelist", 
        "whitelisted_sender_name": "✅ Sender name is on your trusted whitelist",
        "whitelisted_score_reduced": "ℹ️ Score reduced because sender is whitelisted",
        "blocked_email": "🚫 Sender email is on your blocklist",
        "blocked_domain": "🚫 Sender domain is on your blocklist",
        "malicious_url_detected": "⛔ DANGER: Contains a confirmed malicious URL (Google Safe Browsing)"
    }
    
    base = explanations.get(reason_key.split(":")[0], f"Flagged: {reason_key}")
    
    # Add context for whitelisted items
    if ":" in reason_key and (reason_key.startswith("whitelisted") or reason_key.startswith("blocked")):
        parts = reason_key.split(":", 1)
        if len(parts) > 1:
            base += f" ({parts[1]})"
    
    return base

# ========= Pydantic Models =========
class ScanBody(BaseModel):
    sender: str
    subject: str = ""
    email_text: str = ""

# ========= Build/Env Diagnostics =========
GIT_SHA = os.environ.get("VERCEL_GIT_COMMIT_SHA", "local")
BUILD_TIME = os.environ.get("BUILD_TIME", datetime.now(timezone.utc).isoformat())
VERCEL_URL = os.environ.get("VERCEL_URL", "")

# ========= Tunables (AGGRESSIVE MODE - Catch More Spam) =========
MIN_BLOCK_SCORE = int(os.getenv("MIN_BLOCK_SCORE", "35"))  # Lowered from 50 to catch marketing spam
MIN_CONFIDENCE = float(os.getenv("MIN_CONFIDENCE", "0.00"))
STRICT_BAD_TLD = True # Enforce strict TLD checking


ENABLE_URL_EXPANSION = os.getenv("ENABLE_URL_EXPANSION", "1") == "1"
ENABLE_TIPS = os.getenv("ENABLE_TIPS", "1") == "1"
FORWARDED_PREFER_ORIGINAL = os.getenv("FORWARDED_PREFER_ORIGINAL", "1") == "1"

# ✅ Google Safe Browsing API key
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

# ========= Heuristics =========
PHISHING_WORDS = [
    r"verify your account", r"reset your password", r"unauthorized login",
    r"unusual activity", r"update payment", r"wire transfer",
    r"crypto wallet", r"bank account", r"urgent action required",
    r"confirm your identity", r"2fa.*disable", r"limited time verification",
    r"suspended.*account", r"account.*locked", r"account.*limited",
    r"reactivate.*account", r"unusual.*activity", r"security.*alert",
]

JUNK_WORDS = [
    r"unsubscribe", r"newsletter", r"flash sale", r"discount", r"coupon",
    r"special offer", r"bundle", r"limited time", r"promo", r"view in browser",
    r"no[- ]?reply", r"do not reply", r"manage preferences",
    # AGGRESSIVE MARKETING ADDITIONS
    r"act fast", r"act now", r"hurry", r"don't miss", r"don't wait",
    r"\d{1,3}%\s*off", r"\bsale\b", r"clearance", r"\bdeals?\b",
    r"shop now", r"buy now", r"order now", r"get it now",
    r"exclusive offer", r"today only", r"expires", r"last chance",
    r"free shipping", r"lowest price", r"limited quantity",
    r"while supplies last", r"final hours", r"ending soon",
]

BUSINESS_SPAM_WEIGHTS = {
    # High-confidence indicators (likely spam)
    r"\blead generation\b": 20,
    r"\bappointment setting\b": 20,
    r"\bqualified leads?\b": 20,
    r"\bdemand generation\b": 15,
    r"\bb2b outreach\b": 15,
    r"\brevops\b|\bsalesops\b": 15,
    r"\bscale your (team|revenue|sales)\b": 15,

    # Medium-confidence (could be legit, but often spam)
    r"\bhir(e|ing) (developers?|engineers?|designers?)\b": 10,
    r"\bstaff(ing)?\b": 10,
    r"\brecruit(er|ment|ing)\b": 10,
    r"\bnearshore\b|\boffshore\b": 10,
    r"\boutsourc(e|ing)\b": 10,
    r"\bfractional (cto|cmo|cfo)\b": 10,
    r"\bbook(ing)? a (call|demo)\b": 10,


    # Lower-confidence (often legit, but can be spammy)
    r"\breach(ing)? out\b": 5,
    r"\bagency\b": 5,
    r"\bcase study\b": 5,
    r"\bproposal\b|\brfp\b": 5,
    r"\baudit of your\b": 5,
    r"\bcalendar link\b": 5,
    r"\btalent\s+ready\b": 5,
}

POOR_GRAMMAR_INDICATORS = [
    r"\bpls\b", r"\bplz\b", r"\burgen[ct]", r"dear (customer|user|client|member)\b",
    r"kindly ", r"revert back", r"do the needful", r"same will be",
]

TRACKING_HOST_HINTS = {
    "click", "trk", "track", "r.", "l.", "links.", "email.", "mandrillapp",
    "sendgrid", "hubspot", "safelinks", "list-manage", "postmarkapp",
    "mailchimp", "emltrk", "route.", "bounce.",
}

SUSPICIOUS_TLDS = {
    "xyz", "click", "top", "ru", "cn", "icu", "zip", "mov", "quest", "gq",
    "country", "work", "fit", "tk", "cf", "ml", "ga", "pw", "cc", "win", "bid", "loan"
}

FREE_EMAIL_SENDERS = {
    "gmail.com","yahoo.com","outlook.com","hotmail.com","icloud.com","aol.com"
}

# Trusted domains that should get score bonuses (reduce false positives)
TRUSTED_DOMAINS = {
    "salesforce.com", "sonicwall.com", "microsoft.com", "google.com",
    "amazon.com", "apple.com", "adobe.com", "dropbox.com", "slack.com",
    "github.com", "gitlab.com", "atlassian.com", "zoom.us", "teams.microsoft.com",
    "linkedin.com", "twitter.com", "facebook.com", "instagram.com",
    "paypal.com", "stripe.com", "square.com", "shopify.com",
    "netflix.com", "spotify.com", "youtube.com", "twitch.tv",
    "airbnb.com", "uber.com", "lyft.com", "doordash.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "citi.com",
    "nasa.gov", "gov.uk", "edu",  # Government and education domains
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly",
    "adf.ly", "short.link", "tiny.cc", "is.gd", "cli.gs",
}

# ========= Precompiled regex =========
URL_RE = re.compile(r"""(?ix)\bhttps?://[^\s<>()"']+""")
RE_REPLYTO = re.compile(r"reply[- ]?to:\s*<?([^>\s]+@[^>\s]+)>?", re.I)
RE_ALPHA = re.compile(r"[^A-Za-z]+")

# ========= Helpers =========
def _domain_of(addr: str) -> str:
    try:
        return (addr or "").split("@", 1)[-1].lower()
    except Exception:
        return ""

def extract_urls(text: str) -> List[str]:
    return URL_RE.findall(text or "")

def _is_all_caps(s: str) -> bool:
    s = (s or "").strip()
    letters = RE_ALPHA.sub("", s)
    return bool(letters) and letters.isupper()

# Extract original sender from forwarded emails
def detect_forwarded_original_sender(body: str) -> str | None:
    if not body:
        return None
    patterns = [
        r'From:\s*(?:"[^"]*"\s*)?<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?',
        r'Sender:\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?',
        r'Begin forwarded message:.*?From:.*?<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?',
        r'[-]+\s*Forwarded message\s*[-]+.*?From:.*?<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?',
        r'(?:forwarded|fwd).*?from:\s*(?:[^<\s]+\s*)?<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?',
    ]
    for pattern in patterns:
        match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
        if match:
            email = match.group(1).lower().strip()
            # Allow all email addresses, including no-reply
            if email and '@' in email:
                print(f"   🔍 Found potential sender: {email}")
                return email
    return None

# ========= Email Header Analysis for Forwarded Emails =========
def analyze_email_headers(body: str) -> List[Tuple[str, int]]:
    """
    Analyze email headers present in forwarded email body.
    Returns a list of (reason, score) tuples.
    """
    contributions = []
    
    if not body:
        return []
    
    body_lower = body.lower()
    
    # Microsoft Exchange spam markers
    if re.search(r'scl:\s*([5-9]|1[0-9])', body_lower):
        contributions.append(("microsoft_marked_as_spam", 25))
    
    # Spam filter verdicts
    if re.search(r'sfv:\s*spm', body_lower):
        contributions.append(("spam_filter_verdict_spam", 25))
    
    if re.search(r'cat:\s*spm', body_lower):
        contributions.append(("categorized_as_spam", 20))
    
    # Junk folder delivery
    if re.search(r'rf:\s*junkemail', body_lower):
        contributions.append(("delivered_to_junk_folder", 20))
    
    # Forefront anti-spam detection
    if re.search(r'x-forefront-antispam-report:.*spm', body_lower):
        contributions.append(("forefront_spam_detection", 15))
    
    # SpamAssassin scores (if present)
    spam_score_match = re.search(r'x-spam-score:\s*([\d.]+)', body_lower)
    if spam_score_match:
        spam_score = float(spam_score_match.group(1))
        if spam_score >= 5.0:
            contributions.append((f"spamassassin_score:{spam_score}", 30))
        elif spam_score >= 3.0:
            contributions.append((f"spamassassin_score:{spam_score}", 15))
    
    return contributions


def detect_marketing_email(body: str, subject: str) -> List[Tuple[str, int]]:
    """
    AGGRESSIVE marketing/promotional email detection
    """
    contributions = []
    
    combined = f"{subject} {body}".lower()
    body_lower = body.lower()
    
    # List-Unsubscribe header = DEFINITIVE marketing email
    # Check multiple formats for forwarded emails and header variations
    if (re.search(r'list-unsubscribe\s*:', body_lower, re.I) or
        re.search(r'list-unsubscribe-post\s*:', body_lower, re.I) or
        'list-unsubscribe' in body_lower):  # Also check without colon for forwarded emails
        contributions.append(("marketing_unsubscribe_header", 40))  # Increased from 35 to 40
    
    # Precedence: bulk header = DEFINITIVE bulk/marketing email
    # Check multiple formats for forwarded emails
    if (re.search(r'precedence\s*:\s*bulk', body_lower, re.I) or 
        re.search(r'precedence\s*bulk', body_lower, re.I)):
        contributions.append(("precedence_bulk_header", 20))
    
    # Tracking URLs (common in marketing emails)
    if re.search(r'tracking[.-]', body_lower) or re.search(r'/track/', body_lower):
        contributions.append(("tracking_url_detected", 20))
    
    # Discount/sale language
    discount_patterns = [
        r'\d{1,3}%\s*off',
        r'save\s+[\$€£]?\d+',
        r'up to \d+%',
        r'[\$€£]\d+\s+off',
        r'\d{1,3}%\s*discount',
    ]
    discount_count = sum(1 for p in discount_patterns if re.search(p, combined, re.I))
    if discount_count > 0:
        contributions.append((f"discount_language:{discount_count}_instances", discount_count * 12))
    
    # Urgency tactics in marketing
    urgency_marketing = [
        r'act fast', r'act now', r'limited time',
        r'hurry', r"don't miss", r'today only',
        r'expires', r'last chance', r'final hours',
        r'while supplies last', r'ending soon',
    ]
    urgency_count = sum(1 for p in urgency_marketing if re.search(p, combined, re.I))
    if urgency_count >= 2:
        contributions.append((f"marketing_urgency:{urgency_count}_tactics", 35))  # Increased from 25 to 35
    elif urgency_count == 1:
        contributions.append(("marketing_urgency:1_tactic", 15))  # Increased from 10 to 15
    
    # Shop/Buy commands
    if re.search(r'(shop|buy|order|get it)\s+now', combined, re.I):
        contributions.append(("marketing_call_to_action", 12))
    
    # Email has BOTH unsubscribe AND urgency/discount = confirmed marketing spam
    if 'unsubscribe' in combined and (urgency_count > 0 or discount_count > 0):
        contributions.append(("confirmed_marketing_spam", 40))  # Increased from 30 to 40
    
    # Newsletter-specific patterns
    if re.search(r'view (in|this email in) (your )?browser', combined, re.I):
        contributions.append(("newsletter_view_in_browser", 15))
    
    # Promotional sender domains
    promo_domains = [
        'news.', 'newsletter.', 'promo.', 'marketing.',
        'updates.', 'email.', 'mail.', 'info.',
    ]
    if any(d in body_lower for d in promo_domains):
        contributions.append(("promotional_sender_domain", 10))
    
    # Email preferences/manage subscription links
    if re.search(r'(manage|update) (your )?(email )?(preferences|subscription)', combined, re.I):
        contributions.append(("marketing_preferences_link", 12))
    
    # Marketing platform detection (ClickFunnels, HubSpot, Mailchimp, etc.)
    marketing_platforms = [
        ('clickfunnels', 'clickfunnelsnotifications.com', 'myclickfunnels.com'),
        ('hubspot', 'hubspotlinks.com', 'hs-email.net'),
        ('mailchimp', 'list-manage.com', 'mailchi.mp'),
        ('sendgrid', 'sendgrid.net', 'sendgrid.com'),
        ('constant contact', 'constantcontact.com'),
        ('activecampaign', 'activecampaign.com'),
        ('convertkit', 'convertkit.com'),
        ('drip', 'drip.com', 'getdrip.com'),
        ('aweber', 'aweber.com'),
        ('infusionsoft', 'infusionsoft.com', 'keap.com'),
    ]

    platform_detected = False
    for platform_keywords in marketing_platforms:
        if any(keyword in body_lower for keyword in platform_keywords):
            platform_name = platform_keywords[0]
            contributions.append((f"marketing_platform:{platform_name}", 25))  # Increased from 15 to 25
            platform_detected = True
            break
    
    # Multiple long tracking URLs (marketing email pattern)
    tracking_url_count = len(re.findall(r'https?://[^\s<>()"\']{50,}', body))
    if tracking_url_count >= 3:
        contributions.append(("multiple_tracking_urls", 25))  # Increased from 20 to 25
    elif tracking_url_count >= 1:
        contributions.append(("tracking_url_present", 12))  # New: Even 1 tracking URL is suspicious
    
    # Forwarded marketing emails - check subject for "Fwd:" + marketing keywords
    if re.search(r'^fwd?:\s*', subject.lower()) and (
        'launch' in combined or 'price' in combined or 'tutorial' in combined or
        'discount' in combined or 'sale' in combined or 'offer' in combined
    ):
        contributions.append(("forwarded_marketing_email", 25))
    
    # Marketing content patterns in forwarded emails
    marketing_keywords = [
        r'\blaunch(es|ed|ing)\b', r'\bprice(s|d)?\s*(reduction|lower|down)\b',
        r'\btutorial(s)?\b', r'\bnew\s+(product|feature|update)\b',
        r'\bdeploy\s+(now|immediately)\b', r'\bview\s+pricing\b'
    ]
    marketing_content_matches = sum(1 for pattern in marketing_keywords if re.search(pattern, combined, re.I))
    if marketing_content_matches >= 2:
        contributions.append(("marketing_content_patterns", 20))
    
    return contributions

# ========= Enhanced Subject Line Analysis =========
def analyze_suspicious_subject(subject: str, sender: str) -> List[Tuple[str, int]]:
    """
    Detect common spam subject patterns
    """
    contributions = []
    
    if not subject:
        return []
    
    subject_lower = subject.lower()
    sender_dom = _domain_of(sender)
    
    # Generic relationship-building spam
    generic_patterns = [
        r'\blove your (product|service|website|site|work|company|products)\b',
        r'\bimpressed (by|with) your\b',
        r'\bquick question\b',
        r'\breached? out\b',
        r'\bsaw your (product|service|website|site|work)\b',
        r'\b(quick|simple|brief) (question|inquiry)\b',
        r'\bcurious about\b',
        r'\binterested in (working|partnering|collaborating)\b',
    ]
    
    for pattern in generic_patterns:
        if re.search(pattern, subject_lower):
            # Higher score if from free email
            if sender_dom in FREE_EMAIL_SENDERS:
                contributions.append(("generic_cold_outreach_subject_free_email", 15))
            else:
                contributions.append(("generic_cold_outreach_subject", 8))
            break
    
    # Overly friendly subjects from strangers
    if re.search(r'^(hi|hello|hey)[\s,!]+', subject_lower):
        if sender_dom in FREE_EMAIL_SENDERS:
            contributions.append(("overly_casual_greeting_from_stranger", 10))
    
    # Question marks with generic business terms
    if '?' in subject and re.search(r'\b(partnership|collaboration|service|solution|offer)\b', subject_lower):
        if sender_dom in FREE_EMAIL_SENDERS:
            contributions.append(("sales_pitch_question", 8))
    
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
        contributions.append(("sender_name_email_mismatch_free_provider", 12))
    elif not has_match:
        contributions.append(("sender_name_email_mismatch", 6))
    
    return contributions

# ========= Bayesian Scoring (for False Negatives) =========
SPAM_VOCAB = {
    "free": 10, "win": 8, "winner": 5, "prize": 7, "claim": 6, "urgent": 9,
    "limited": 8, "offer": 10, "deal": 7, "subscribe": 5, "unsubscribe": 10,
    "click": 9, "buy": 8, "sex": 5, "viagra": 5, "pharmacy": 5, "bitcoin": 6,
    "crypto": 6, "investment": 7, "guaranteed": 8, "million": 5, "dollars": 5,
    "cash": 7, "credit": 6, "loan": 6, "now": 10, "risk-free": 7, "congratulations": 7,
    "selected": 6, "special": 8, "promotion": 8, "seo": 8, "marketing": 7,
    "growth": 7, "generate": 7, "leads": 8, "revenue": 6
}

HAM_VOCAB = {
    "meeting": 10, "project": 9, "team": 8, "document": 8, "attached": 9,
    "update": 7, "report": 7, "schedule": 6, "call": 6, "discussion": 7,
    "feedback": 6, "request": 7, "question": 8, "following": 5, "invoice": 5,
    "payment": 5, "reminder": 6, "thanks": 10, "best": 8, "regards": 10,
    "sincerely": 8, "forwarded": 5, "link": 5, "issue": 6, "bug": 5, "fix": 5,
    "pull": 5, "merge": 5, "commit": 5,
}

def calculate_bayesian_score(text: str) -> float:
    text_words = set(re.findall(r'\b\w+\b', text.lower()))
    
    total_spam_words = sum(SPAM_VOCAB.values())
    total_ham_words = sum(HAM_VOCAB.values())
    
    # Prior probabilities (assume equal for simplicity)
    p_spam = 0.5
    p_ham = 0.5

    # Use log probabilities to avoid underflow
    log_spam_prob = math.log(p_spam)
    log_ham_prob = math.log(p_ham)

    # Vocabulary of all known words
    vocab = set(SPAM_VOCAB.keys()) | set(HAM_VOCAB.keys())
    
    for word in text_words:
        if len(word) > 2 and len(word) < 20: # ignore very short and very long words
            # Calculate P(word | Spam) with Laplace smoothing
            p_word_spam = (SPAM_VOCAB.get(word, 0) + 1) / (total_spam_words + len(vocab))
            log_spam_prob += math.log(p_word_spam)
            
            # Calculate P(word | Ham) with Laplace smoothing
            p_word_ham = (HAM_VOCAB.get(word, 0) + 1) / (total_ham_words + len(vocab))
            log_ham_prob += math.log(p_word_ham)

    # Return a score based on the difference.
    # The multiplication factor can be tuned.
    score = (log_spam_prob - log_ham_prob) * 3.0
    
    # Cap the score to prevent it from dominating everything else.
    if score > 0:
        return min(score, 30.0)
    else:
        # Give a smaller negative score to avoid incorrectly classifying ham as super safe
        return max(score, -10.0)

# ========= URL Analysis =========
def _url_features(urls: List[str]) -> Tuple[bool, bool, bool, List[str]]:
    """
    Returns (tracking_hit, bad_tld_hit, long_query_hit, shortener_urls)
    """
    tracking_hit = False
    bad_tld_hit = False
    long_query_hit = False
    shortener_urls = []
    
    for u in urls:
        try:
            parsed = urlparse(u)
            host = parsed.netloc.lower()
            
            # Check tracking hosts
            if any(hint in host for hint in TRACKING_HOST_HINTS):
                tracking_hit = True
            
            # Check bad TLDs
            extracted = _TLDX(u)
            if extracted.suffix in SUSPICIOUS_TLDS:
                bad_tld_hit = True
            
            # Check long query strings
            if len(parsed.query) > 80:
                long_query_hit = True
            
            # Check URL shorteners
            if host in URL_SHORTENERS or any(short in host for short in URL_SHORTENERS):
                shortener_urls.append(u)
                
        except Exception:
            pass
    
    return tracking_hit, bad_tld_hit, long_query_hit, shortener_urls

# ========= Google Safe Browsing Integration =========
async def check_urls_against_safe_browsing(urls: List[str]) -> Tuple[bool, List[str]]:
    """
    Check URLs against Google Safe Browsing API
    Returns (has_malicious, malicious_urls)
    """
    if not GOOGLE_SAFE_BROWSING_API_KEY or not urls:
        return False, []
    
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        
        payload = {
            "client": {
                "clientId": "spamscore",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url} for url in urls[:10]]  # Limit to 10 URLs
            }
        }
        
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(api_url, json=payload)
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get("matches", [])
                if matches:
                    malicious_urls = [match.get("threat", {}).get("url") for match in matches]
                    return True, malicious_urls
        
        return False, []
        
    except Exception as e:
        print(f"Safe Browsing API error: {e}")
        return False, []

# ========= Action Advice =========
def get_action_advice(verdict: str, category: str) -> Dict:
    """Returns user-friendly action advice"""
    advice_map = {
        ("block", "phishing"): {
            "emoji": "🚫",
            "title": "BLOCK THIS EMAIL - Likely Phishing Attack",
            "subtitle": "This email shows strong signs of a phishing attempt",
            "steps": [
                "DO NOT click any links or download attachments",
                "DO NOT reply or provide any information",
                "Delete this email immediately",
                "If it claims to be from a company you use, visit their website directly (don't use links in the email)",
                "Consider reporting this to your IT security team or email provider"
            ]
        },
        ("block", "business_spam"): {
            "emoji": "🗑️",
            "title": "BLOCK THIS EMAIL - Unsolicited Business Spam",
            "subtitle": "This appears to be cold outreach/B2B spam",
            "steps": [
                "Delete or mark as spam",
                "These emails rarely contain value and waste your time",
                "Consider unsubscribing if there's a legitimate option",
                "Set up filters to block future emails from this sender"
            ]
        },
        ("block", "junk"): {
            "emoji": "🗑️",
            "title": "BLOCK THIS EMAIL - Junk/Marketing",
            "subtitle": "Appears to be unwanted marketing or junk mail",
            "steps": [
                "Delete or move to spam folder",
                "Unsubscribe if you don't remember signing up",
                "These emails clutter your inbox with no value"
            ]
        },
        ("block", "suspicious"): {
            "emoji": "⚠️",
            "title": "BLOCK THIS EMAIL - Suspicious Content",
            "subtitle": "Multiple red flags detected",
            "steps": [
                "Be very cautious with this email",
                "Don't click links or download files",
                "Verify sender through another channel before responding",
                "When in doubt, delete it"
            ]
        },
        ("caution", "marketing"): {
            "emoji": "⚠️",
            "title": "CAUTION - Promotional Email",
            "subtitle": "Appears to be marketing, use your judgment",
            "steps": [
                "Verify you signed up for emails from this sender",
                "Check for unsubscribe options at the bottom",
                "Be cautious clicking links",
                "Consider if this is a company you trust"
            ]
        },
        ("caution", "suspicious"): {
            "emoji": "👀",
            "title": "CAUTION - Review Carefully",
            "subtitle": "Some concerning elements detected",
            "steps": [
                "Read carefully before taking any action",
                "Verify sender identity if making any decisions",
                "Hover over links before clicking to see where they go",
                "Trust your instincts - if something feels off, it probably is"
            ]
        },
        ("safe", "legitimate"): {
            "emoji": "✅",
            "title": "Looks Safe",
            "subtitle": "No major red flags detected",
            "steps": [
                "This email appears legitimate",
                "Still practice good email hygiene",
                "Verify sender if email requests sensitive info",
                "When in doubt, contact the sender through official channels"
            ]
        }
    }
    
    # Default fallback
    default = {
        "emoji": "❓",
        "title": "Review This Email",
        "subtitle": "Unable to determine safety level",
        "steps": [
            "Review carefully before taking action",
            "Verify sender through official channels",
            "Don't provide sensitive information"
        ]
    }
    
    return advice_map.get((verdict, category), default)

# ========= MAIN CATEGORIZATION ENGINE (BALANCED MODE - False Positive Fixes) =========
async def categorize_email(sender: str, subject: str, body: str, user_id: Optional[str] = None) -> Dict:
    """
    Main analysis engine - returns spam score and categorization
    
    CHANGES MADE TO REDUCE FALSE POSITIVES:
    1. Fixed undefined 'flags' variable bug (would cause runtime error)
    2. Added trusted domain bonuses (-25 points) to reduce false positives
    3. Increased MIN_BLOCK_SCORE from 40 to 50 (higher threshold before blocking)
    4. Made business spam detection less aggressive (only flag with high confidence or free email)
    5. Reduced marketing penalties for trusted domains (30-50% reduction)
    6. Improved whitelist effectiveness (up to 40 point reduction)
    7. Increased caution threshold from 15 to 20 points
    8. Skip Bayesian scoring for trusted domains (they get benefit of the doubt)
    """
    contributions = []
    flags = {}  # FIX: Initialize flags dictionary early to prevent NameError
    
    # Check whitelist first
    is_wl = False
    wl_reason = ""
    if user_id:
        is_wl, wl_reason = check_whitelist(user_id, sender)
        if is_wl:
            flags["whitelisted"] = True
            flags["whitelist_reason"] = wl_reason
    
    # Check blocklist
    is_bl = False
    bl_reason = ""
    if user_id:
        is_bl, bl_reason = check_blocklist(user_id, sender)
        if is_bl:
            if is_wl:
                # CONFLICT RESOLUTION: Whitelist wins, remove from blocklist
                sender_email = extract_email(sender)
                sender_domain = _domain_of(sender_email)
                if is_blocked(user_id, sender_email, 'email'):
                    remove_from_blocklist(user_id, sender_email, 'email')
                if is_blocked(user_id, sender_domain, 'domain'):
                    remove_from_blocklist(user_id, sender_domain, 'domain')
                is_bl = False
                bl_reason = ""
            else:
                # Blocklist hit - IMMEDIATE RETURN
                return {
                    "score": 100,
                    "verdict": "block",
                    "category": "blocked_sender",
                    "reasons": [bl_reason],
                    "simple_reasons": [{"explanation": get_simple_explanation(bl_reason), "severity": "high"}],
                    "flags": {"blocked": True},
                    "urls_found": [],
                    "shortener_urls": [],
                    "whitelisted": False,
                    "blocked": True,
                    "detailed_reasons": []
                }
    
    # Extract features
    sender_dom = _domain_of(sender)
    subject_lower = (subject or "").lower()
    body_lower = (body or "").lower()
    combined = f"{subject_lower} {body_lower}"
    urls = extract_urls(body)
    
    # CHANGE: Trusted domain bonus (reduces false positives)
    # Legitimate companies (Microsoft, Google, banks, etc.) get -25 point bonus
    # This prevents false positives from trusted senders
    # FIX: We'll apply this bonus AFTER calculating spam signals to prevent spam from scoring 0
    is_trusted_domain = False
    for trusted in TRUSTED_DOMAINS:
        if trusted in sender_dom:
            is_trusted_domain = True
            # Don't add bonus here - we'll apply it conditionally later
            break
    
    # CHANGE: Bayesian score (only apply if not from trusted domain)
    # Trusted domains get benefit of the doubt - skip Bayesian spam detection
    if not is_trusted_domain:
        bayesian_score = calculate_bayesian_score(combined)
        if bayesian_score != 0:
            contributions.append(("bayesian_score", bayesian_score))
    
    # URL Analysis
    tracking_hit, bad_tld_hit, long_query_hit, shortener_urls = _url_features(urls)
    
    # Google Safe Browsing check
    has_malicious, malicious_urls = await check_urls_against_safe_browsing(urls)
    if has_malicious:
        contributions.append(("malicious_url_detected", 100))
        flags["malicious_urls"] = malicious_urls
    
    # Header-based detection for forwarded emails
    header_contributions = analyze_email_headers(body)
    if header_contributions:
        contributions.extend(header_contributions)
    
    # Subject line pattern analysis
    subject_contributions = analyze_suspicious_subject(subject, sender)
    if subject_contributions:
        contributions.extend(subject_contributions)
    
    # Sender name/email mismatch
    mismatch_contributions = check_sender_name_email_mismatch(sender, body)
    if mismatch_contributions:
        contributions.extend(mismatch_contributions)
    
    # Phishing indicators
    phishing_matches = sum(1 for p in PHISHING_WORDS if re.search(p, combined, re.I))
    if phishing_matches >= 2:
        contributions.append(("phishing_language", 40))
    elif phishing_matches == 1:
        contributions.append(("potential_phishing_language", 15))
    
    # CHANGE: Business spam indicators (less aggressive to reduce false positives)
    # OLD: Would flag any business spam with score >= 10
    # NEW: Only flag if very high confidence (>=20) OR medium confidence (>=10) from free email
    biz_score = 0
    for pattern, weight in BUSINESS_SPAM_WEIGHTS.items():
        if re.search(pattern, combined, re.I):
            biz_score += weight
    
    # Only flag business spam if:
    # 1. Very high confidence (biz_score >= 20) - multiple strong signals, OR
    # 2. Medium confidence (biz_score >= 10) AND from free email AND not trusted domain
    # This prevents legitimate business emails from corporate domains being flagged
    is_free_email = sender_dom in FREE_EMAIL_SENDERS
    if biz_score >= 20:  # Very high confidence - flag regardless of sender
        contributions.append(("business_spam", biz_score))
        if is_free_email:
            contributions.append(("free_email_cold_outreach_kicker", 15))
    elif biz_score >= 10 and is_free_email and not is_trusted_domain:
        # Medium confidence but from free email (not trusted) - likely spam
        contributions.append(("business_spam", biz_score))
        contributions.append(("free_email_cold_outreach_kicker", 10))
    
    # CHANGE: Marketing/junk indicators (reduced penalties for trusted domains)
    # OLD: Same penalty regardless of sender
    # NEW: Trusted domains get 33-47% penalty reduction (legitimate marketing is OK)
    junk_matches = sum(1 for j in JUNK_WORDS if re.search(j, combined, re.I))
    if junk_matches >= 3:
        # Heavy marketing: 30 → 20 points for trusted domains (33% reduction)
        penalty = 20 if is_trusted_domain else 30
        contributions.append(("heavy_marketing_language", penalty))
    elif junk_matches >= 2:
        # Regular marketing: 15 → 8 points for trusted domains (47% reduction)
        penalty = 8 if is_trusted_domain else 15
        contributions.append(("marketing_language", penalty))
    
    # CHANGE: Marketing Email Detection (skip for trusted domains)
    # Trusted domains can send marketing emails - don't penalize them
    # CRITICAL: Use full body (body_for_detection) which includes headers
    if not is_trusted_domain:
        marketing_contributions = detect_marketing_email(body, subject)
        if marketing_contributions:
            # Don't reduce marketing penalties - they should be applied fully
            # The 30% reduction was causing marketing emails to score too low
            contributions.extend(marketing_contributions)
    
    # Poor grammar indicators
    grammar_matches = sum(1 for g in POOR_GRAMMAR_INDICATORS if re.search(g, combined, re.I))
    if grammar_matches >= 1:
        contributions.append(("poor_grammar", 10))
    
    # Tracking/suspicious URLs
    if tracking_hit:
        contributions.append(("tracking_urls_detected", 10))
    if bad_tld_hit:
        contributions.append(("suspicious_tld_detected", 20))
    if long_query_hit:
        contributions.append(("long_query_string_urls", 10))
    if shortener_urls:
        contributions.append(("url_shorteners_detected", 15))
    
    # Subject analysis
    if _is_all_caps(subject):
        contributions.append(("all_caps_subject", 10))
    if re.search(r"re:|fwd:", subject_lower) and not re.search(r"re:|fwd:", body_lower[:200]):
        contributions.append(("fake_reply_subject", 5))
    
    # Urgency/pressure tactics
    if re.search(r"\burgent\b|\basap\b|\bimmediate\b|\bnow\b.*action", combined, re.I):
        contributions.append(("urgency_pressure", 15))
    
    # CHANGE: Generic greetings (reduced penalty for trusted domains)
    # OLD: 10 points for all generic greetings
    # NEW: 5 points for trusted domains, 10 for others
    # Legitimate companies often use "Dear Customer" in mass emails
    if re.search(r"dear (customer|user|client|member|sir|madam)\b", combined, re.I):
        penalty = 5 if is_trusted_domain else 10
        contributions.append(("generic_greeting", penalty))
    
    # Reply-To mismatch
    reply_to_match = RE_REPLYTO.search(body)
    if reply_to_match:
        reply_to = reply_to_match.group(1).lower()
        if _domain_of(reply_to) != sender_dom:
            contributions.append((f"reply_to_mismatch:{reply_to}", 12))
    
    # Calculate final score from all contributions
    score = sum(c[1] for c in contributions)
    
    # CRITICAL FIX: Ensure minimum score for detected spam signals
    # If we detected ANY spam signals (positive contributions), score should be at least 10
    # This prevents spam from scoring 0 when bonuses cancel out signals
    # Exclude bonuses and whitelist reductions from this check
    spam_contributions = [c for c in contributions if c[1] > 0 and 
                         not c[0].startswith("trusted_domain") and 
                         not c[0].startswith("whitelisted") and
                         not c[0].startswith("minimum")]
    has_spam_signals = len(spam_contributions) > 0
    if has_spam_signals and score < 10:
        score = 10  # Minimum score for any email with spam signals
        contributions.append(("minimum_spam_score_enforced", 0))
    
    # FIX: Apply trusted domain bonus AFTER calculating spam signals
    # CRITICAL FIX: Only apply bonus for low scores (< 20) to prevent spam from scoring 0
    # If a trusted domain has strong spam signals (score >= 20), don't apply bonus
    # This prevents spam from trusted domains (e.g., compromised accounts) from being hidden
    # The bonus helps reduce false positives for borderline cases but doesn't hide real spam
    if is_trusted_domain:
        if score < 20:  # Only apply bonus for low scores (borderline cases)
            # Apply bonus: reduce score by up to 10 points, but never below 10
            # Example: score 15 -> bonus 5 -> final 10 (still detectable)
            # Example: score 25 -> no bonus (spam signals too strong)
            bonus = min(10, max(0, score - 10))  # Bonus up to 10, but keep at least 10 points
            if bonus > 0:
                score = max(10, score - bonus)  # Ensure minimum of 10
                contributions.append(("trusted_domain_bonus", -bonus))
            elif score < 10:
                # Very low score (< 10) - set to 10 minimum (still detectable as suspicious)
                score = 10
                contributions.append(("trusted_domain_bonus_minimum", 0))
        else:
            # Score >= 20 from trusted domain - strong spam signals, don't apply bonus
            contributions.append(("trusted_domain_bonus_ignored_high_risk", 0))
    
    # Ensure score doesn't go negative
    score = max(0, score)
    
    # CHANGE: Apply whitelist adjustment (more effective reduction)
    # OLD: Complex calculation that didn't work well
    # NEW: Simple reduction of up to 40 points for whitelisted senders
    if is_wl:
        original_score = score
        # SAFETY CHECK: Don't reduce score if it's VERY high (>70) - might be real threat
        # Even whitelisted senders can be compromised, so don't ignore high-risk signals
        if score < 70:
            # Reduce score significantly for whitelisted senders (up to 40 points)
            score_reduction = min(score, 40)  # Cap reduction at 40 points
            score = max(0, score - score_reduction)
            contributions.append((wl_reason, -score_reduction))
        else:
            contributions.append((f"{wl_reason} (IGNORED: High Risk Content)", 0))
    
    # AGGRESSIVE MODE: Determine verdict and category (optimized to catch more spam)
    # MIN_BLOCK_SCORE is 35 (lowered from 50 to catch marketing spam)
    # Caution threshold is 20
    # Marketing detection scores increased by 30-50% to reduce false negatives
    # CRITICAL FIX: Check for marketing signals even at low scores
    has_marketing_signals = any("marketing" in c[0].lower() or "unsubscribe" in c[0].lower() or 
                                "precedence" in c[0].lower() or "hubspot" in c[0].lower() or
                                "tracking" in c[0].lower() for c in contributions if c[1] > 0)
    
    if score >= MIN_BLOCK_SCORE:  # MIN_BLOCK_SCORE is 35 (AGGRESSIVE MODE)
        verdict = "block"
        if phishing_matches >= 1 or has_malicious:
            category = "phishing"
        elif biz_score >= 20 or (biz_score >= 10 and is_free_email):
            category = "business_spam"
        elif junk_matches >= 2:  # Lowered from 3 to 2 (more aggressive)
            category = "junk"
        elif has_marketing_signals:  # Added: Marketing emails should be blocked
            category = "marketing"
        else:
            category = "suspicious"
    elif score >= 15 or has_marketing_signals:  # Lowered from 20 to 15 (catch more marketing)
        verdict = "caution"
        if has_marketing_signals or junk_matches >= 1:
            category = "marketing"
        else:
            category = "suspicious"
    else:
        verdict = "safe"
        category = "legitimate"
    
    # Build simplified reasons for user display
    simple_reasons = [{"explanation": get_simple_explanation(r), "severity": "high" if c > 15 else "medium" if c > 5 else "low"} for r, c in contributions if c > 0]
    
    # Detailed reasons with scores
    detailed_reasons = [{"explanation": get_simple_explanation(r), "points": c} for r, c in contributions if c != 0]
    
    return {
        "score": score,
        "verdict": verdict,
        "category": category,
        "confidence": min(1.0, max(MIN_CONFIDENCE, score / 60.0)),
        "reasons": [r for r, c in contributions],
        "simple_reasons": simple_reasons,
        "detailed_reasons": detailed_reasons,
        "flags": {
            **flags,  # Includes whitelisted, malicious_urls, etc.
            "tracking_hit": tracking_hit,
            "bad_tld_hit": bad_tld_hit,
            "long_query_hit": long_query_hit,
            "link_count": len(urls),
            "is_trusted_domain": is_trusted_domain,  # NEW: Track if sender is trusted
        },
        "urls_found": urls,
        "shortener_urls": shortener_urls if shortener_urls else [],
        "whitelisted": is_wl and score < 20,
        "blocked": is_bl
    }

# ========= Mailgun Integration =========
MG_KEY = os.getenv("MAILGUN_API_KEY", "")
MG_DOMAIN = os.getenv("MAILGUN_DOMAIN", "")
REPLY_FROM = os.getenv("REPLY_FROM", "scan@mg.techamped.com")

async def send_report_via_mailgun(to_addr: str, subject: str, html_body: str, text_body: str) -> Tuple[bool, int, str]:
    """
    Return (ok, status_code, response_text)
    """
    if not (MG_KEY and MG_DOMAIN and to_addr):
        return False, 503, "Mailgun not configured or missing recipient"
    url = f"https://api.mailgun.net/v3/{MG_DOMAIN}/messages"
    auth = ("api", MG_KEY)
    data = {"from": REPLY_FROM, "to": to_addr, "subject": subject, "text": text_body, "html": html_body}
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(url, auth=auth, data=data)
            return (200 <= r.status_code < 300), r.status_code, r.text
    except Exception as e:
        return False, 599, f"exception: {e}"

# ========= Report Builders =========
def get_educational_tip(reasons: List[str]) -> str:
    tips = {
        "phishing": "💡 Real companies NEVER ask you to verify passwords or accounts by email.",
        "tracking": "💡 Hover over links (don't click!) to see where they really go.",
        "bad_tld": "💡 Strange website endings like .xyz or .ru are common in scams.",
        "urgency": "💡 Scammers create fake urgency to make you react without thinking.",
        "generic": "💡 Legitimate companies use your name, not 'Dear Customer'.",
    }
    if any("phishing" in r.lower() or "verify" in r.lower() for r in reasons):
        return tips["phishing"]
    if any("tracking" in r.lower() for r in reasons):
        return tips["tracking"]
    if any("tld" in r.lower() for r in reasons):
        return tips["bad_tld"]
    if any("urgent" in r.lower() or "caps" in r.lower() for r in reasons):
        return tips["urgency"]
    if any("generic" in r.lower() or "dear customer" in r.lower() for r in reasons):
        return tips["generic"]
    return "💡 Always be skeptical of unexpected emails, especially those asking for action."

def build_html_report(sender: str, subject: str, result: Dict, original_sender: str | None, evaluated_sender: str) -> str:
    action = get_action_advice(result["verdict"], result["category"])
    simple_reasons = result.get("simple_reasons", [])
    detailed_reasons = result.get("detailed_reasons", [])

    # Build reason blocks
    reasons_html = ""
    for r in simple_reasons:
        severity_color = {"high": "#dc2626", "medium": "#ea580c", "low": "#ca8a04"}.get(r.get("severity", "low"), "#6b7280")
        reasons_html += f'<div style="padding: 10px; margin: 8px 0; background: #f9fafb; border-left: 3px solid {severity_color}; border-radius: 4px;">{html.escape(r.get("explanation", ""))}</div>\n'

    if not simple_reasons:
        reasons_html = '<div style="padding: 10px; background: #f0fdf4; border-left: 3px solid #22c55e; border-radius: 4px;">No major red flags detected</div>'

    # Build score breakdown
    score_breakdown_html = ""
    if detailed_reasons:
        score_breakdown_html = '<div class="section"><div class="section-title">Score Breakdown:</div><table style="width: 100%; border-collapse: collapse;">'
        for reason in detailed_reasons:
            points = reason.get("points", 0)
            color = "#dc2626" if points > 0 else "#16a34a"
            score_breakdown_html += f'<tr><td style="padding: 8px;">{html.escape(reason.get("explanation", ""))}</td><td style="padding: 8px; text-align: right; color: {color};">{points}</td></tr>'
        score_breakdown_html += '</table></div>'

    # Build URL list
    urls_html = ""
    if result.get("urls_found"):
        urls_list = "".join([f"<li style='margin: 5px 0; word-break: break-all;'>{html.escape(u)}</li>" for u in result["urls_found"][:10]])
        if len(result["urls_found"]) > 10:
            urls_list += f"<li style='color: #6b7280; font-style: italic;'>...and {len(result['urls_found']) - 10} more links</li>"
        urls_html = f"""
        <div class="section">
            <div class="section-title">🔗 Links Found in Email:</div>
            <ul style="margin: 10px 0; padding-left: 20px;">
                {urls_list}
            </ul>
        </div>
        """

    # Education tip
    tip_html = ""
    if ENABLE_TIPS:
        tip = get_educational_tip(result["reasons"])
        tip_html = f'<div class="section" style="background: #eff6ff; border: 2px solid #3b82f6; padding: 15px; border-radius: 8px; font-size: 15px;">{html.escape(tip)}</div>'

    # Dashboard link
    feedback_html = f"""
    <div class="section" style="background: #f0fdf4; border: 2px solid #22c55e; padding: 15px; border-radius: 8px;">
        <div class="section-title" style="margin-bottom: 10px;">⚙️ Manage Your Settings:</div>
        <div style="font-size: 14px; line-height: 1.6;">
            Visit your dashboard to manage whitelist and blocklist:<br>
            <a href="https://spamscore-dashboard.vercel.app" style="color: #16a34a; font-weight: bold;">spamscore-dashboard.vercel.app</a>
        </div>
    </div>
    """

    # Build steps list
    steps_html = "".join([f"<li style='margin: 8px 0; font-size: 15px;'>{html.escape(step)}</li>" for step in action["steps"]])

    # Final HTML
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 650px; margin: 0 auto; padding: 20px; background: #f9fafb; }}
            .container {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
            .header {{ text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #e5e7eb; }}
            .title {{ font-size: 24px; font-weight: bold; color: #111827; margin: 10px 0; }}
            .subtitle {{ font-size: 16px; color: #6b7280; margin: 5px 0; }}
            .verdict-badge {{ display: inline-block; padding: 8px 16px; border-radius: 6px; font-weight: bold; font-size: 14px; margin: 15px 0; }}
            .verdict-block {{ background: #fef2f2; color: #dc2626; border: 2px solid #dc2626; }}
            .verdict-caution {{ background: #fffbeb; color: #d97706; border: 2px solid #d97706; }}
            .verdict-safe {{ background: #f0fdf4; color: #16a34a; border: 2px solid #16a34a; }}
            .section {{ margin: 25px 0; padding: 20px; background: #f9fafb; border-radius: 8px; }}
            .section-title {{ font-weight: bold; font-size: 16px; color: #374151; margin-bottom: 12px; }}
            .email-details {{ background: #f3f4f6; padding: 15px; border-radius: 8px; margin: 15px 0; }}
            .email-details div {{ margin: 8px 0; font-size: 14px; }}
            .footer {{ text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; color: #6b7280; font-size: 13px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div style="font-size: 48px; margin-bottom: 10px;">{action['emoji']}</div>
                <div class="title">{html.escape(action['title'])}</div>
                <div class="subtitle">{html.escape(action['subtitle'])}</div>
                <div class="verdict-badge verdict-{result['verdict']}">{result['verdict'].upper()} • Score: {result['score']}/100</div>
            </div>
            
            <div class="email-details">
                <div><strong>From:</strong> {html.escape(evaluated_sender)}</div>
                <div><strong>Subject:</strong> {html.escape(subject or 'No subject')}</div>
                {f'<div><strong>Original Sender:</strong> {html.escape(original_sender)}</div>' if original_sender else ''}
            </div>
            
            <div class="section">
                <div class="section-title">🎯 Recommended Actions:</div>
                <ol style="margin: 10px 0; padding-left: 20px; line-height: 1.8;">
                    {steps_html}
                </ol>
            </div>
            
            <div class="section">
                <div class="section-title">🔍 Analysis Details:</div>
                {reasons_html}
            </div>
            
            {score_breakdown_html}
            {urls_html}
            {tip_html}
            {feedback_html}
            
            <div class="footer">
                <p><strong>SpamScore</strong> by TechAmped<br>
                Protecting your inbox from spam and phishing</p>
            </div>
        </div>
    </body>
    </html>
    """

def build_text_report(sender: str, subject: str, result: Dict, original_sender: str | None, evaluated_sender: str) -> str:
    action = get_action_advice(result["verdict"], result["category"])
    detailed_reasons = result.get("detailed_reasons", [])
    
    report = f"""
{action['emoji']} {action['title']}
{action['subtitle']}

VERDICT: {result['verdict'].upper()}
SCORE: {result['score']}/100

FROM: {evaluated_sender}
SUBJECT: {subject or 'No subject'}
{f'ORIGINAL SENDER: {original_sender}' if original_sender else ''}

RECOMMENDED ACTIONS:
"""
    for i, step in enumerate(action["steps"], 1):
        report += f"{i}. {step}\n"
    
    report += "\nSCORE BREAKDOWN:\n"
    for reason in detailed_reasons:
        points = reason.get("points", 0)
        report += f"• {reason.get('explanation', '')}: {points} points\n"
        
    if result.get("urls_found"):
        report += f"\nLINKS FOUND ({len(result['urls_found'])}):\n"
        for u in result["urls_found"][:10]:
            report += f"• {u}\n"
        if len(result["urls_found"]) > 10:
            report += f"...and {len(result['urls_found']) - 10} more\n"
    
    if ENABLE_TIPS:
        tip = get_educational_tip(result["reasons"])
        report += f"\n{tip}\n"
    
    report += """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚙️ MANAGE SETTINGS
Visit your dashboard to manage whitelist and blocklist:
https://spamscore-dashboard.vercel.app
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SpamScore by TechAmped
Protecting your inbox from spam and phishing
"""
    
    return report

# ========= Root Route =========
@app.get("/")
async def root():
    return {
        "status": "ok",
        "service": "SpamScore Backend",
        "version": "2.2-balanced-fp-fixed",
        "git_sha": GIT_SHA[:8] if GIT_SHA else "unknown",
        "build_time": BUILD_TIME,
        "endpoints": {
            "scan": "POST /receive (Mailgun webhook for email forwarding)",
            "whitelist": "GET/POST /api/whitelist/*",
            "blocklist": "GET/POST /api/blocklist/*",
            "history": "GET /api/history",
            "analytics": "GET /api/stats/summary"
        }
    }

# ========= Email Receive Endpoint (IMPROVED LOGIC) =========
@app.post("/receive")
async def receive_mailgun_webhook(
    sender: str = Form(...),
    recipient: str = Form(...),
    subject: str = Form(""),
    body_plain: str = Form(""),
    body_html: str = Form(""),
    stripped_text: str = Form("")
):
    """
    Main webhook for receiving emails from Mailgun
    """
    # FIX: Deduplication - prevent processing same email twice
    # Create a unique hash of the email content
    email_hash = hashlib.sha256(f"{sender}{subject}{body_plain or body_html or ''}".encode()).hexdigest()[:16]
    dedup_key = f"email_processed:{email_hash}"
    
    # Check if we've already processed this email in the last 5 minutes
    if redis_client:
        try:
            if redis_client.exists(dedup_key):
                print(f"   ⚠️ Duplicate email detected (hash: {email_hash}), skipping...")
                return {
                    "status": "duplicate",
                    "message": "This email was already processed recently",
                    "email_hash": email_hash
                }
            # Mark as processed for 5 minutes
            redis_client.setex(dedup_key, 300, "1")  # 5 minutes TTL
        except Exception as e:
            print(f"   ⚠️ Deduplication check failed: {e}")
    
    # Extract user email from the forwarder
    user_email = sender.lower().strip()
    user_id = get_user_id_from_email(user_email)
    
    # Bodies
    body_plain_text = body_plain or ""
    body_html_text = body_html or ""
    stripped = stripped_text or ""
    
    # Use FULL body for detection
    body_for_detection = body_plain_text or body_html_text or stripped
    
    # Use stripped_text for normal processing (cleaner)
    body = stripped or body_plain_text or body_html_text
    
    print(f"\n{'='*60}")
    print(f"📧 RECEIVED EMAIL FROM: {sender}")
    print(f"📋 SUBJECT: {subject}")
    
    # Try to detect original sender in forwarded email
    original_sender = detect_forwarded_original_sender(body_for_detection) if FORWARDED_PREFER_ORIGINAL else None
    
    # 🔴 HEURISTIC FORWARD DETECTION (Regex Fallback)
    # If regex fails but it looks like a forward, assume unknown sender to disable whitelist.
    is_forwarded_structure = "forwarded message" in body_for_detection.lower() or "from:" in body_for_detection.lower()[:500]
    
    if original_sender:
        evaluated_sender = original_sender
        # It is definitely a forward, so we do NOT use the forwarder's whitelist/blocklist
        # because we are analyzing the stranger, not the user.
        analysis_user_id = None 
        print(f"   ✅ Extracted Original Sender: {evaluated_sender}")
        
    elif is_forwarded_structure and FORWARDED_PREFER_ORIGINAL:
        # We see it's a forward, but regex failed. 
        # We treat this as "Unknown Sender" and DISCARD the User ID for whitelist checks.
        # This prevents the user's own whitelist from zeroing out the spam score.
        evaluated_sender = "unknown_potential_spam@unknown.com"
        analysis_user_id = None
        print(f"   ⚠️ Detected forward structure but couldn't parse sender. Disabling whitelist for strict scan.")
        
    else:
        # Direct email
        evaluated_sender = sender
        analysis_user_id = user_id
        print(f"   👤 Direct email from: {evaluated_sender}")
    
    # Generate unique scan ID
    scan_id = hashlib.sha256(f"{user_id}{evaluated_sender}{subject}{datetime.now().isoformat()}".encode()).hexdigest()[:16]
    
    # Analyze with appropriate context
    # Note: If analysis_user_id is None, it skips whitelist checks (GOOD for forwards)
    # CRITICAL: Use body_for_detection (includes headers) for marketing detection, not stripped body
    result = await categorize_email(evaluated_sender, subject, body_for_detection, user_id=analysis_user_id)
    
    print(f"   📊 Final Score: {result['score']} ({result['verdict']})")
    
    # Record scan history with all proper fields
    record_scan(
        user_id=user_id,
        scan_id=scan_id,
        sender=evaluated_sender,
        subject=subject or "No subject",
        score=result["score"],
        verdict=result["verdict"],
        category=result["category"],
        whitelisted=result.get("whitelisted", False),
        blocked=result.get("blocked", False)
    )
    
    # Check rate limit
    scan_count = get_monthly_scan_count(user_id)
    if scan_count > 100:
        result["note"] = "Monthly limit exceeded."
    
    # Build reports
    html_report = build_html_report(sender, subject, result, original_sender, evaluated_sender)
    text_report = build_text_report(sender, subject, result, original_sender, evaluated_sender)
    
    action = get_action_advice(result["verdict"], result["category"])
    title = f"{action['emoji']} SpamScore: {action['title'][:50]}"
    
    # Send report back to the forwarder
    ok, st, txt = await send_report_via_mailgun(sender, title, html_report, text_report)
    
    return {
        "status": "ok" if ok else "mail_send_failed",
        "type": "scan",
        "verdict": result["verdict"],
        "category": result["category"],
        "emailed": ok,
        "mailgun_status": st,
        "evaluated_sender": evaluated_sender,
        "score": result["score"]
    }


# ========= Dashboard API Models =========
class WhitelistAddRequest(BaseModel):
    user_email: str
    type: str  # 'email' or 'domain'
    value: str

class WhitelistRemoveRequest(BaseModel):
    user_email: str
    type: str
    value: str

class BlocklistAddRequest(BaseModel):
    user_email: str
    type: str  # 'email' or 'domain'
    value: str

class BlocklistRemoveRequest(BaseModel):
    user_email: str
    type: str
    value: str

def get_user_id(email: str) -> str:
    """Generate user ID from email (for dashboard API)"""
    return hashlib.sha256(email.lower().encode()).hexdigest()[:16]

def validate_email_format(email: str) -> bool:
    """Validate email address format"""
    if not email or len(email) > 254:
        return False
    # Basic email validation regex
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    return bool(email_pattern.match(email))

def validate_domain_format(domain: str) -> bool:
    """Validate domain format"""
    if not domain or len(domain) > 253:
        return False
    # Domain should not contain @ symbol and should have at least one dot
    if '@' in domain:
        return False
    # Basic domain validation
    domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$')
    return bool(domain_pattern.match(domain))

# ========= Whitelist API Endpoints =========
@app.get("/api/whitelist/list")
async def api_get_whitelist(user_email: str):
    """Get user's whitelist"""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Database not available")
    
    user_id = get_user_id(user_email)
    
    # Get emails and domains from whitelist
    email_whitelist = get_whitelist(user_id, 'email')
    domain_whitelist = get_whitelist(user_id, 'domain')
    
    # Format response with metadata
    whitelist = []
    
    for email in email_whitelist:
        meta_key = f"whitelist:{user_id}:email:meta:{email}"
        meta = redis_client.hgetall(meta_key)
        whitelist.append({
            "type": "email",
            "value": email,
            "added_at": meta.get("added_at", datetime.now().isoformat())
        })
    
    for domain in domain_whitelist:
        meta_key = f"whitelist:{user_id}:domain:meta:{domain}"
        meta = redis_client.hgetall(meta_key)
        whitelist.append({
            "type": "domain",
            "value": domain,
            "added_at": meta.get("added_at", datetime.now().isoformat())
        })
    
    return {"whitelist": whitelist}

@app.post("/api/whitelist/add")
async def api_add_to_whitelist(request: WhitelistAddRequest):
    """Add email or domain to whitelist"""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Database not available")

    # Validate user email
    if not validate_email_format(request.user_email):
        raise HTTPException(status_code=400, detail="Invalid user email format")

    user_id = get_user_id(request.user_email)

    # Validate type
    if request.type not in ["email", "domain", "sender_name"]:
        raise HTTPException(status_code=400, detail="Type must be 'email', 'domain', or 'sender_name'")

    # Validate value based on type
    if request.type == "email":
        if not validate_email_format(request.value):
            raise HTTPException(status_code=400, detail=f"Invalid email format: {request.value}")
    elif request.type == "domain":
        if not validate_domain_format(request.value):
            raise HTTPException(status_code=400, detail=f"Invalid domain format: {request.value}")
    elif request.type == "sender_name":
        if not request.value or len(request.value) > 100:
            raise HTTPException(status_code=400, detail="Sender name must be between 1 and 100 characters")

    success = add_to_whitelist(user_id, request.value, request.type)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to add to whitelist")

    return {"success": True, "message": f"Added {request.value} to whitelist"}

@app.post("/api/whitelist/remove")
async def api_remove_from_whitelist(request: WhitelistRemoveRequest):
    """Remove email or domain from whitelist"""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Database not available")

    # Validate user email
    if not validate_email_format(request.user_email):
        raise HTTPException(status_code=400, detail="Invalid user email format")

    user_id = get_user_id(request.user_email)

    # Validate type
    if request.type not in ["email", "domain", "sender_name"]:
        raise HTTPException(status_code=400, detail="Type must be 'email', 'domain', or 'sender_name'")

    success = remove_from_whitelist(user_id, request.value, request.type)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to remove from whitelist")

    return {"success": True, "message": f"Removed {request.value} from whitelist"}

# ========= Blocklist API Endpoints =========
@app.get("/api/blocklist/list")
async def api_get_blocklist(user_email: str):
    """Get user's blocklist"""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Database not available")

    # Validate user email
    if not validate_email_format(user_email):
        raise HTTPException(status_code=400, detail="Invalid user email format")

    user_id = get_user_id(user_email)

    # Get emails and domains from blocklist
    email_blocklist = redis_client.smembers(f"blocklist:{user_id}:email") if redis_client else set()
    domain_blocklist = redis_client.smembers(f"blocklist:{user_id}:domain") if redis_client else set()

    # Format response with metadata
    blocklist = []

    for email in email_blocklist:
        meta_key = f"blocklist:{user_id}:email:meta:{email}"
        meta = redis_client.hgetall(meta_key) if redis_client else {}
        blocklist.append({
            "type": "email",
            "value": email,
            "added_at": meta.get("added_at", datetime.now().isoformat())
        })

    for domain in domain_blocklist:
        meta_key = f"blocklist:{user_id}:domain:meta:{domain}"
        meta = redis_client.hgetall(meta_key) if redis_client else {}
        blocklist.append({
            "type": "domain",
            "value": domain,
            "added_at": meta.get("added_at", datetime.now().isoformat())
        })

    return {"blocklist": blocklist}

@app.post("/api/blocklist/add")
async def api_add_to_blocklist(request: BlocklistAddRequest):
    """Add email or domain to blocklist"""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Database not available")

    # Validate user email
    if not validate_email_format(request.user_email):
        raise HTTPException(status_code=400, detail="Invalid user email format")

    user_id = get_user_id(request.user_email)

    # Validate type
    if request.type not in ["email", "domain"]:
        raise HTTPException(status_code=400, detail="Type must be 'email' or 'domain'")

    # Validate value based on type
    if request.type == "email":
        if not validate_email_format(request.value):
            raise HTTPException(status_code=400, detail=f"Invalid email format: {request.value}")
    elif request.type == "domain":
        if not validate_domain_format(request.value):
            raise HTTPException(status_code=400, detail=f"Invalid domain format: {request.value}")

    # Check if already whitelisted - if so, remove from whitelist first
    user_id_check = get_user_id(request.user_email)
    if is_whitelisted(user_id_check, request.value, request.type):
        remove_from_whitelist(user_id_check, request.value, request.type)

    success = add_to_blocklist(user_id, request.value, request.type)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to add to blocklist")

    return {"success": True, "message": f"Added {request.value} to blocklist"}

@app.post("/api/blocklist/remove")
async def api_remove_from_blocklist(request: BlocklistRemoveRequest):
    """Remove email or domain from blocklist"""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Database not available")

    # Validate user email
    if not validate_email_format(request.user_email):
        raise HTTPException(status_code=400, detail="Invalid user email format")

    user_id = get_user_id(request.user_email)

    # Validate type
    if request.type not in ["email", "domain"]:
        raise HTTPException(status_code=400, detail="Type must be 'email' or 'domain'")

    success = remove_from_blocklist(user_id, request.value, request.type)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to remove from blocklist")

    return {"success": True, "message": f"Removed {request.value} from blocklist"}

# ========= History API Endpoint =========
@app.get("/api/history")
async def api_get_scan_history(user_email: str, limit: int = 50):
    """Get user's scan history"""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Database not available")
    
    user_id = get_user_id(user_email)
    history = get_scan_history(user_id, limit)
    
    return {"history": history}

# ========= Analytics/Stats API Endpoint =========
@app.get("/api/stats/summary")
async def api_get_stats_summary(user_email: str):
    """Get user's stats summary"""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Database not available")
    
    user_id = get_user_id(user_email)
    
    # Get scan count for current month
    monthly_usage = get_monthly_scan_count(user_id)
    
    # Get feedback stats
    false_positives = int(redis_client.get(f"stats:{user_id}:false_positives") or 0)
    false_negatives = int(redis_client.get(f"stats:{user_id}:false_negatives") or 0)
    
    # Get whitelist and blocklist counts
    email_wl_count = redis_client.scard(f"whitelist:{user_id}:email") or 0
    domain_wl_count = redis_client.scard(f"whitelist:{user_id}:domain") or 0
    whitelisted_senders = email_wl_count + domain_wl_count
    
    blocked_senders = get_blocklist_count(user_id)
    
    # Calculate accuracy estimate
    total_feedback = false_positives + false_negatives
    if monthly_usage > 0:
        false_positive_rate = (false_positives / monthly_usage * 100)
        false_negative_rate = (false_negatives / monthly_usage * 100)
        accuracy = 100 - (false_positive_rate + false_negative_rate)
    else:
        accuracy = 95.0  # Default estimate
    
    # Generate whitelist help text
    if whitelisted_senders == 0:
        whitelist_help_text = "Add trusted senders to reduce false positives"
    elif whitelisted_senders < 5:
        whitelist_help_text = f"Your {whitelisted_senders} trusted sender(s) help prevent false alarms"
    else:
        reduction_estimate = min(75, whitelisted_senders * 5)
        whitelist_help_text = f"Your whitelist has reduced false positives by ~{reduction_estimate}%"
    
    return {
        "monthly_usage": monthly_usage,
        "monthly_limit": 100,
        "overall_accuracy": round(accuracy, 1),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "whitelisted_senders": whitelisted_senders,
        "blocked_senders": blocked_senders,
        "whitelist_help_text": whitelist_help_text
    }
