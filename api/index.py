# ===========================
# api/index.py — FIXED VERSION
# ===========================

import os, re, html
from typing import List, Dict, Tuple
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import FastAPI, Query, Form, Request
from pydantic import BaseModel
import httpx
import tldextract

# Use read-only friendly extractor on Vercel
_TLDX = tldextract.TLDExtract(cache_dir=None)

app = FastAPI()

# ========= Pydantic Models =========
class ScanBody(BaseModel):
    sender: str
    subject: str = ""
    email_text: str = ""

# ========= Build/Env Diagnostics =========
GIT_SHA = os.environ.get("VERCEL_GIT_COMMIT_SHA", "local")
BUILD_TIME = os.environ.get("BUILD_TIME", datetime.now(timezone.utc).isoformat())
VERCEL_URL = os.environ.get("VERCEL_URL", "")

# ========= Tunables =========
MIN_BLOCK_SCORE = int(os.getenv("MIN_BLOCK_SCORE", "20"))
MIN_CONFIDENCE = float(os.getenv("MIN_CONFIDENCE", "0.00"))
STRICT_BAD_TLD = os.getenv("STRICT_BAD_TLD", "1") == "1"
BUSINESS_SPAM_PENALTY = int(os.getenv("BUSINESS_SPAM_PENALTY", "12"))
FREE_EMAIL_COLD_OUTREACH_PENALTY = int(os.getenv("FREE_EMAIL_COLD_OUTREACH_PENALTY", "15"))

ENABLE_URL_EXPANSION = os.getenv("ENABLE_URL_EXPANSION", "1") == "1"
ENABLE_TIPS = os.getenv("ENABLE_TIPS", "1") == "1"

# ✅ Prefer original sender when parsing forwarded emails
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
]

BUSINESS_SPAM_WORDS = [
    r"\btalent\s+ready\b",
    r"\bhir(e|ing) (developers?|engineers?|designers?)\b",
    r"\bstaff(ing)?\b",
    r"\brecruit(er|ment|ing)\b",
    r"\bagency\b",
    r"\bbook(ing)? a (call|demo)\b",
    r"\blead generation\b",
    r"\bqualified leads?\b",
    r"\bnearshore\b|\boffshore\b",
    r"\boutsourc(e|ing)\b",
    r"\bfractional (cto|cmo|cfo)\b",
    r"\bappointment setting\b",
    r"\bdemand generation\b",
    r"\bb2b outreach\b",
    r"\bcase study\b",
    r"\bproposal\b|\brfp\b",
    r"\baudit of your\b",
    r"\brevops\b|\bsalesops\b",
    r"\bcalendar link\b",
    r"\bscale your (team|revenue|sales)\b",
    r"\breach(ing)? out\b",
]

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
    "country", "work", "fit", "tk", "cf", "ml", "ga", "pw", "cc",
}

FREE_EMAIL_SENDERS = {
    "gmail.com","yahoo.com","outlook.com","hotmail.com","icloud.com","aol.com"
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
            if email and '@' in email and not email.startswith('no-reply'):
                return email
    return None

# ========= Email Header Analysis for Forwarded Emails =========
def analyze_email_headers(body: str) -> Tuple[int, List[str]]:
    """
    Analyze email headers present in forwarded email body.
    Returns (score_adjustment, reasons)
    """
    score = 0
    reasons = []
    
    if not body:
        return 0, []
    
    body_lower = body.lower()
    
    # Microsoft Exchange spam markers
    if re.search(r'scl:\s*([5-9]|1[0-9])', body_lower):
        score += 25
        reasons.append("microsoft_marked_as_spam")
    
    # Spam filter verdicts
    if re.search(r'sfv:\s*spm', body_lower):
        score += 25
        reasons.append("spam_filter_verdict_spam")
    
    if re.search(r'cat:\s*spm', body_lower):
        score += 20
        reasons.append("categorized_as_spam")
    
    # Junk folder delivery
    if re.search(r'rf:\s*junkemail', body_lower):
        score += 20
        reasons.append("delivered_to_junk_folder")
    
    # Forefront anti-spam detection
    if re.search(r'x-forefront-antispam-report:.*spm', body_lower):
        score += 15
        reasons.append("forefront_spam_detection")
    
    # SpamAssassin scores (if present)
    spam_score_match = re.search(r'x-spam-score:\s*([\d.]+)', body_lower)
    if spam_score_match:
        spam_score = float(spam_score_match.group(1))
        if spam_score >= 5.0:
            score += 30
            reasons.append(f"spamassassin_score:{spam_score}")
        elif spam_score >= 3.0:
            score += 15
            reasons.append(f"spamassassin_score:{spam_score}")
    
    # Barracuda spam scores
    if re.search(r'x-barracuda-spam-score:\s*([5-9]|[1-9][0-9])', body_lower):
        score += 25
        reasons.append("barracuda_spam_score_high")
    
    return score, reasons

# ========= Enhanced Subject Line Analysis =========
def analyze_suspicious_subject(subject: str, sender: str) -> Tuple[int, List[str]]:
    """
    Detect common spam subject patterns
    """
    score = 0
    reasons = []
    
    if not subject:
        return 0, []
    
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
                score += 15
                reasons.append("generic_cold_outreach_subject_free_email")
            else:
                score += 8
                reasons.append("generic_cold_outreach_subject")
            break
    
    # Overly friendly subjects from strangers
    if re.search(r'^(hi|hello|hey)[\s,!]+', subject_lower):
        if sender_dom in FREE_EMAIL_SENDERS:
            score += 10
            reasons.append("overly_casual_greeting_from_stranger")
    
    # Question marks with generic business terms
    if '?' in subject and re.search(r'\b(partnership|collaboration|service|solution|offer)\b', subject_lower):
        if sender_dom in FREE_EMAIL_SENDERS:
            score += 8
            reasons.append("sales_pitch_question")
    
    return score, reasons

# ========= Sender Name vs Email Mismatch Detection =========
def check_sender_name_email_mismatch(sender: str, body: str) -> Tuple[int, List[str]]:
    """
    Detect when sender name doesn't match email address (common in spam)
    Example: "John Smith <randomshop123@gmail.com>"
    """
    score = 0
    reasons = []
    
    # Extract display name if present
    name_match = re.search(r'^([^<]+)<([^>]+)>$', sender.strip())
    if not name_match:
        return 0, []
    
    display_name = name_match.group(1).strip().lower()
    email_addr = name_match.group(2).strip().lower()
    
    # Remove quotes from display name
    display_name = display_name.strip('"').strip("'")
    
    # Skip if display name is empty or just email
    if not display_name or '@' in display_name:
        return 0, []
    
    # Get email username part
    email_username = email_addr.split('@')[0].lower()
    
    # Extract name components
    name_parts = re.findall(r'[a-z]{3,}', display_name)
    
    # Check if ANY name part appears in email username
    has_match = any(part in email_username for part in name_parts if len(part) >= 3)
    
    if not has_match:
        # Name and email completely unrelated
        if _domain_of(email_addr) in FREE_EMAIL_SENDERS:
            score += 12
            reasons.append("sender_name_email_mismatch_free_provider")
        else:
            score += 6
            reasons.append("sender_name_email_mismatch")
    
    return score, reasons

# ========= Google Safe Browsing Integration =========
async def check_urls_against_safe_browsing(urls: List[str]) -> Tuple[bool, List[str]]:
    """
    Check URLs against Google Safe Browsing API.
    Returns (has_malicious_urls, list_of_malicious_urls)
    """
    if not GOOGLE_SAFE_BROWSING_API_KEY or not urls:
        return False, []

    urls_to_check = urls[:10]
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"

    payload = {
        "client": {"clientId": "spamscore", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls_to_check],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(api_url, json=payload)
            if response.status_code == 200:
                data = response.json()
                if data.get("matches"):
                    malicious_urls = [m["threat"]["url"] for m in data["matches"]]
                    return True, malicious_urls
                return False, []
            else:
                return False, []
    except Exception:
        return False, []

# ========= URL feature extraction =========
def _url_features(urls: List[str]) -> Tuple[bool, bool, bool, List[str]]:
    tracking_hit = False
    bad_tld_hit = False
    long_query_hit = False
    shortener_urls = []
    for u in urls:
        try:
            parsed = urlparse(u)
            host = parsed.netloc.lower()
            if any(short in host for short in URL_SHORTENERS):
                shortener_urls.append(u)
            ext = _TLDX(u)
            sub = (ext.subdomain or "").lower()
            suf = (ext.suffix or "").lower()
            if any(h in host or (sub and sub.startswith(h.rstrip("."))) for h in TRACKING_HOST_HINTS):
                tracking_hit = True
            if suf.split(".")[-1] in SUSPICIOUS_TLDS:
                bad_tld_hit = True
            if len(u) > 150 or ("?" in u and len(u.split("?", 1)[-1]) > 100):
                long_query_hit = True
        except Exception:
            continue
    return tracking_hit, bad_tld_hit, long_query_hit, shortener_urls

# ========= Friendly Explanation Mapping =========
def get_simple_explanation(reason_key: str, context: Dict = None) -> str:
    context = context or {}
    explanations = {
        "malicious_url_detected": "🚨 This email contains links flagged as dangerous by Google",
        "phishing_language": "⚠️ Uses language commonly found in phishing attempts",
        "marketing_language": "📧 Contains typical marketing/promotional language",
        "business_spam": "💼 Appears to be unsolicited business outreach (B2B spam)",
        "free_email_cold_outreach": "🎣 Cold outreach from a free email provider (red flag)",
        "poor_grammar": "📝 Contains grammatical errors common in scams",
        "tracking_urls_detected": "📊 Contains tracking links that monitor your clicks",
        "suspicious_tld_detected": "🌐 Uses a suspicious website domain ending (.xyz, .ru, etc.)",
        "long_query_string_urls": "🔗 Links have unusually long tracking parameters",
        "url_shorteners_detected": "🔗 Contains shortened URLs that hide the real destination",
        "all_caps_subject": "🗣️ Subject line in ALL CAPS (aggressive marketing tactic)",
        "fake_reply_subject": "↩️ Fake 'Re:' or 'Fwd:' in subject (never started a conversation)",
        "urgency_pressure": "⏰ Creates false urgency to pressure quick action",
        "generic_greeting": "👤 Uses generic greeting instead of your name",
        "reply_to_mismatch": "📬 The 'Reply-To' address differs from sender (red flag)",
        # Header-based detections
        "microsoft_marked_as_spam": "🚩 Microsoft Exchange already flagged this as spam (SCL score)",
        "spam_filter_verdict_spam": "🚩 Email security system marked this as spam",
        "categorized_as_spam": "🚩 Automatically categorized as spam by filters",
        "delivered_to_junk_folder": "🗑️ This was delivered to a junk/spam folder",
        "forefront_spam_detection": "🚩 Forefront anti-spam system detected spam",
        "spamassassin_score": "📊 SpamAssassin gave this a high spam score",
        "barracuda_spam_score_high": "🚩 Barracuda spam filter scored this highly",
        # Subject pattern detections
        "generic_cold_outreach_subject": "📧 Generic cold outreach subject line",
        "generic_cold_outreach_subject_free_email": "🎣 Typical cold spam subject from free email account",
        "overly_casual_greeting_from_stranger": "👋 Overly casual greeting from unknown sender",
        "sales_pitch_question": "💼 Question-based sales pitch pattern",
        # Sender mismatch detections
        "sender_name_email_mismatch": "⚠️ Sender name doesn't match email address",
        "sender_name_email_mismatch_free_provider": "🚨 Sender name completely unrelated to Gmail address (red flag)",
    }
    
    base = explanations.get(reason_key.split(":")[0], f"Flagged: {reason_key}")
    
    # Add count context if present
    if ":" in reason_key:
        parts = reason_key.split(":")
        if len(parts) > 1:
            count_part = parts[1]
            if "_matches" in count_part:
                count = count_part.split("_")[0]
                base += f" ({count} occurrences)"
    
    return base

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

# ========= MAIN CATEGORIZATION ENGINE =========
async def categorize_email(sender: str, subject: str, body: str) -> Dict:
    """
    Main analysis engine - returns spam score and categorization
    """
    score = 0
    reasons = []
    flags = {}
    
    # Extract features
    sender_dom = _domain_of(sender)
    subject_lower = (subject or "").lower()
    body_lower = (body or "").lower()
    combined = f"{subject_lower} {body_lower}"
    urls = extract_urls(body)
    
    # Check URLs for tracking/suspicious patterns
    tracking_hit, bad_tld_hit, long_query_hit, shortener_urls = _url_features(urls)
    
    # Google Safe Browsing check
    has_malicious, malicious_urls = await check_urls_against_safe_browsing(urls)
    if has_malicious:
        score += 50
        reasons.append(f"malicious_url_detected")
        flags["malicious_urls"] = malicious_urls
    
    # ===== NEW: Header-based detection for forwarded emails =====
    header_score, header_reasons = analyze_email_headers(body)
    score += header_score
    reasons.extend(header_reasons)
    
    # ===== NEW: Subject line pattern analysis =====
    subject_score, subject_reasons = analyze_suspicious_subject(subject, sender)
    score += subject_score
    reasons.extend(subject_reasons)
    
    # ===== NEW: Sender name/email mismatch detection =====
    mismatch_score, mismatch_reasons = check_sender_name_email_mismatch(sender, body)
    score += mismatch_score
    reasons.extend(mismatch_reasons)
    
    # Phishing detection
    phishing_matches = sum(1 for p in PHISHING_WORDS if re.search(p, combined, re.I))
    if phishing_matches >= 2:
        score += 30
        reasons.append(f"phishing_language:{phishing_matches}_matches")
    elif phishing_matches == 1:
        score += 15
        reasons.append("phishing_language:1_match")
    
    # Junk/Marketing detection
    junk_matches = sum(1 for j in JUNK_WORDS if re.search(j, combined, re.I))
    if junk_matches >= 3:
        score += 10
        reasons.append(f"marketing_language:{junk_matches}_matches")
    elif junk_matches >= 1:
        score += 5
        reasons.append(f"marketing_indicators:{junk_matches}_matches")
    
    # Business spam detection
    biz_matches = sum(1 for b in BUSINESS_SPAM_WORDS if re.search(b, combined, re.I))
    if biz_matches >= 2:
        score += BUSINESS_SPAM_PENALTY
        reasons.append(f"business_spam:{biz_matches}_matches")
    
    # Free email sender doing cold outreach
    if sender_dom in FREE_EMAIL_SENDERS and biz_matches >= 1:
        score += FREE_EMAIL_COLD_OUTREACH_PENALTY
        reasons.append(f"free_email_cold_outreach")
    
    # Poor grammar indicators
    grammar_matches = sum(1 for g in POOR_GRAMMAR_INDICATORS if re.search(g, combined, re.I))
    if grammar_matches >= 2:
        score += 8
        reasons.append(f"poor_grammar:{grammar_matches}_indicators")
    
    # Tracking/suspicious URLs
    if tracking_hit:
        score += 5
        reasons.append("tracking_urls_detected")
    if bad_tld_hit:
        if STRICT_BAD_TLD:
            score += 15
        else:
            score += 8
        reasons.append("suspicious_tld_detected")
    if long_query_hit:
        score += 5
        reasons.append("long_query_string_urls")
    if shortener_urls:
        score += 8
        reasons.append(f"url_shorteners_detected:{len(shortener_urls)}")
        flags["shortener_urls"] = shortener_urls
    
    # Subject analysis
    if _is_all_caps(subject):
        score += 10
        reasons.append("all_caps_subject")
    if re.search(r"re:|fwd:", subject_lower) and not re.search(r"re:|fwd:", body_lower[:200]):
        score += 5
        reasons.append("fake_reply_subject")
    
    # Urgency/pressure tactics
    if re.search(r"\burgent\b|\basap\b|\bimmediate\b|\bnow\b.*action", combined, re.I):
        score += 8
        reasons.append("urgency_pressure")
    
    # Generic greetings
    if re.search(r"dear (customer|user|client|member|sir|madam)\b", combined, re.I):
        score += 5
        reasons.append("generic_greeting")
    
    # Reply-To mismatch
    reply_to_match = RE_REPLYTO.search(body)
    if reply_to_match:
        reply_to = reply_to_match.group(1).lower()
        if _domain_of(reply_to) != sender_dom:
            score += 12
            reasons.append(f"reply_to_mismatch:{reply_to}")
    
    # Determine verdict and category
    if score >= MIN_BLOCK_SCORE:
        verdict = "block"
        if phishing_matches >= 2 or has_malicious:
            category = "phishing"
        elif biz_matches >= 2:
            category = "business_spam"
        elif junk_matches >= 3:
            category = "junk"
        else:
            category = "suspicious"
    elif score >= 10:
        verdict = "caution"
        category = "marketing" if junk_matches >= 1 else "suspicious"
    else:
        verdict = "safe"
        category = "legitimate"
    
    # Calculate confidence (0.0 to 1.0)
    confidence = min(1.0, max(MIN_CONFIDENCE, score / 50.0))
    
    # Build simplified reasons for user display
    simple_reasons = []
    for reason in reasons:
        explanation = get_simple_explanation(reason)
        severity = "high" if any(x in reason for x in ["malicious", "phishing"]) else \
                   "medium" if any(x in reason for x in ["business_spam", "cold_outreach"]) else "low"
        simple_reasons.append({
            "explanation": explanation,
            "severity": severity
        })
    
    return {
        "score": score,
        "verdict": verdict,
        "category": category,
        "confidence": confidence,
        "reasons": reasons,
        "simple_reasons": simple_reasons,
        "flags": flags,
        "urls_found": urls,
        "shortener_urls": shortener_urls if shortener_urls else []
    }

# ========= Mailgun Integration =========
MG_KEY = os.getenv("MAILGUN_API_KEY", "")
MG_DOMAIN = os.getenv("MAILGUN_DOMAIN", "")
REPLY_FROM = os.getenv("REPLY_FROM", "scan@mg.techamped.com")
REPLY_TO_MODE = os.getenv("REPLY_TO_MODE", "sender")  # "sender" or an explicit email addr

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
    
    # Build reason blocks
    reasons_html = ""
    for r in simple_reasons:
        severity_color = {"high": "#dc2626", "medium": "#ea580c", "low": "#ca8a04"}.get(r.get("severity", "low"), "#6b7280")
        reasons_html += f'<div style="padding: 10px; margin: 8px 0; background: #f9fafb; border-left: 3px solid {severity_color}; border-radius: 4px;">{html.escape(r.get("explanation", ""))}</div>\n'
    
    if not simple_reasons:
        reasons_html = '<div style="padding: 10px; background: #f0fdf4; border-left: 3px solid #22c55e; border-radius: 4px;">No major red flags detected</div>'
    
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
    
    # Action steps
    steps_html = "<br>".join([f"{i+1}. {html.escape(s)}" for i, s in enumerate(action['steps'])])
    
    # Sender info block
    sender_block = f"<strong>From (evaluated):</strong> {html.escape(evaluated_sender or sender or 'Unknown')}<br>"
    if original_sender:
        sender_block += f"<strong>Original sender (detected):</strong> {html.escape(original_sender)}<br>"
    sender_block += f"<strong>Subject:</strong> {html.escape(subject or 'No subject')}"
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; color: #1f2937; margin: 0; padding: 20px; background: #f3f4f6; }}
            .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden; }}
            .header {{ padding: 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-align: center; }}
            .header h1 {{ margin: 0; font-size: 28px; }}
            .header .subtitle {{ margin: 10px 0 0; font-size: 16px; opacity: 0.9; }}
            .content {{ padding: 30px; }}
            .section {{ margin: 25px 0; }}
            .section-title {{ font-size: 18px; font-weight: 600; color: #1f2937; margin-bottom: 12px; }}
            .action-box {{ padding: 20px; background: #fef3c7; border: 2px solid #f59e0b; border-radius: 8px; font-size: 15px; line-height: 1.8; }}
            .confidence {{ margin-top: 15px; font-size: 14px; opacity: 0.9; }}
            .footer {{ padding: 20px; background: #f9fafb; text-align: center; color: #6b7280; font-size: 14px; border-top: 1px solid #e5e7eb; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>{action['emoji']} {html.escape(action['title'])}</h1>
                <div class="subtitle">{html.escape(action['subtitle'])}</div>
                <div class="confidence">Our Confidence: {"⭐" * min(5, int(result["confidence"] * 5 + 1))}</div>
            </div>

            <div class="content">
                <div class="section">
                    <div class="section-title">🛡️ What You Should Do:</div>
                    <div class="action-box">{steps_html}</div>
                </div>

                <div class="section">
                    <div class="section-title">🔍 Why We Think This:</div>
                    {reasons_html}
                </div>

                {urls_html}

                {tip_html}

                <div class="section" style="font-size: 13px; color: #6b7280; border-top: 1px solid #e5e7eb; padding-top: 15px;">
                    {sender_block}
                </div>

                <div class="section" style="border-top: 2px solid #e5e7eb; padding-top: 20px; margin-top: 30px;">
                    <div style="font-size: 14px; color: #4b5563;">
                        <strong>Did we get this wrong?</strong> Reply to this email with:<br>
                        • "SAFE" if this email was actually legitimate<br>
                        • "TRUST sender@example.com" to whitelist emails from someone you know
                    </div>
                </div>
            </div>

            <div class="footer">
                SpamScore Protection Service<br>
                Keeping your inbox safe, one email at a time
            </div>
        </div>
    </body>
    </html>
    """.strip()

def build_text_report(sender: str, subject: str, result: Dict, original_sender: str | None, evaluated_sender: str) -> str:
    action = get_action_advice(result["verdict"], result["category"])
    tip = get_educational_tip(result["reasons"]) if ENABLE_TIPS else ""
    lines = [
        "═" * 50,
        f"{action['emoji']} {action['title']}",
        action['subtitle'],
        "═" * 50,
        "",
        "WHAT TO DO:",
        *[f"  {i+1}. {s}" for i, s in enumerate(action['steps'])],
        "",
        "WHY WE THINK THIS:",
    ]
    for r in result.get("simple_reasons", []):
        sev = r.get("severity", "low")
        icon = "!" if sev in ["critical", "high"] else "•"
        lines.append(f"  {icon} {r.get('explanation','')}")
    if not result.get("simple_reasons"):
        lines.append("  • No major red flags detected")
    if result.get("urls_found"):
        lines.extend(["", "LINKS FOUND:", *[f"  - {u}" for u in result["urls_found"][:5]]])
        if len(result["urls_found"]) > 5:
            lines.append(f"  ...and {len(result['urls_found']) - 5} more")
    if tip:
        lines.extend(["", tip])
    lines.extend([
        "",
        "─" * 50,
        f"From (evaluated): {evaluated_sender or sender or 'Unknown'}",
        *( [f"Original (detected): {original_sender}"] if original_sender else [] ),
        f"Subject: {subject or 'No subject'}",
        "─" * 50,
        "",
        "Reply with:",
        "  • 'SAFE' if this was legitimate",
        "  • 'TRUST sender@example.com' to whitelist someone",
        "",
        "SpamScore Protection Service",
    ])
    return "\n".join(lines)

# ========= Endpoints =========
@app.get("/health")
def health():
    return {"ok": True}

@app.get("/version")
def version():
    return {"git_sha": GIT_SHA, "build_time": BUILD_TIME}

@app.get("/whoami")
def whoami():
    return {"host": VERCEL_URL or "unknown"}

# ----- /scan (JSON API) -----
@app.post("/scan")
async def scan(
    b: ScanBody,
    debug: bool = Query(default=False, description="Return diagnostic fields"),
    expand_short_urls: bool = Query(default=False, description="Try to expand shortened URLs (slower)")
):
    sender = (b.sender or "").strip()
    subject = (b.subject or "").strip()
    body = b.email_text or ""

    original_sender = detect_forwarded_original_sender(body) if FORWARDED_PREFER_ORIGINAL else None
    evaluated_sender = sender
    forwarded_reason = None
    if original_sender and _domain_of(original_sender) != _domain_of(sender):
        evaluated_sender = original_sender
        forwarded_reason = f"Forwarded email detected → using original sender {original_sender} (instead of {sender})"

    result = await categorize_email(evaluated_sender, subject, body)

    # Optional URL expansion
    expanded_urls = {}
    if expand_short_urls and result.get("shortener_urls"):
        for short_url in result["shortener_urls"][:3]:
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    r = await client.head(short_url, follow_redirects=True)
                    if str(r.url) != short_url:
                        expanded_urls[short_url] = str(r.url)
            except Exception:
                continue

    to_addr = sender if (REPLY_TO_MODE == "sender" and "@" in sender) else (REPLY_TO_MODE if "@" in REPLY_TO_MODE else "")
    sent = False
    if to_addr:
        html_report = build_html_report(sender, subject, result, original_sender, evaluated_sender)
        text_report = build_text_report(sender, subject, result, original_sender, evaluated_sender)
        action = get_action_advice(result["verdict"], result["category"])
        title = f"{action['emoji']} SpamScore: {action['title'][:50]}"
        sent, _, _ = await send_report_via_mailgun(to_addr, title, html_report, text_report)

    base = {
        "score": result["score"],
        "verdict": result["verdict"],
        "category": result["category"],
        "confidence": result["confidence"],
        "action_advice": get_action_advice(result["verdict"], result["category"]),
        "original_sender": original_sender or "",
        "evaluated_sender": evaluated_sender,
        "emailed": sent,
    }
    if debug:
        rs = result["reasons"][:]
        if forwarded_reason:
            rs.insert(0, forwarded_reason)
        base["technical_reasons"] = rs
        base["simple_reasons"] = result.get("simple_reasons", [])
        base["flags"] = result.get("flags", {})
        base["urls_found"] = result.get("urls_found", [])
        if expanded_urls:
            base["expanded_urls"] = expanded_urls
    return base

# ----- /receive (Inbound email webhook: Mailgun/SendGrid) -----
@app.post("/receive")
async def receive_email(request: Request):
    """
    Mailgun / SendGrid inbound webhook.
    We parse multipart form manually to avoid alias issues (e.g., 'body-plain').
    """
    try:
        form = await request.form()
    except Exception as e:
        return {"status": "bad_request", "error": f"form_parse_failed: {e}"}

    # Common fields across Mailgun / SendGrid
    sender  = (form.get("sender") or form.get("from") or "").strip()
    subject = (form.get("subject") or "").strip()

    # Prefer plain text, but fall back gracefully
    body = (
        form.get("body-plain") or
        form.get("body_plain")  or
        form.get("text")        or
        form.get("body-html")   or
        form.get("body_html")   or
        form.get("html")        or
        ""
    )

    # Forwarded original sender (if enabled)
    original_sender = detect_forwarded_original_sender(body) if FORWARDED_PREFER_ORIGINAL else None
    evaluated_sender = original_sender if original_sender else sender

    # Analyze
    result = await categorize_email(evaluated_sender, subject, body)

    # Build reports
    html_report = build_html_report(sender, subject, result, original_sender, evaluated_sender)
    text_report = build_text_report(sender, subject, result, original_sender, evaluated_sender)

    action = get_action_advice(result["verdict"], result["category"])
    title = f"{action['emoji']} SpamScore: {action['title'][:50]}"

    # Send report back to the forwarder
    ok, st, txt = await send_report_via_mailgun(sender, title, html_report, text_report)

    return {
        "status": "ok" if ok else "mail_send_failed",
        "verdict": result["verdict"],
        "category": result["category"],
        "emailed": ok,
        "mailgun_status": st,
        "mailgun_response": txt[:1000],
        "original_sender": original_sender or "",
        "evaluated_sender": evaluated_sender or sender,
    }