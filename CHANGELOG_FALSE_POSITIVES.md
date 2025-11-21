# False Positive Fixes - Changelog

## Overview
This document explains all changes made to `api/index.py` to reduce false positives while maintaining strong spam detection.

## Version
Updated from `2.1-aggressive` to `2.2-balanced-fp-fixed`

---

## 1. Critical Bug Fix

### Issue
- **Line 1059**: `flags` variable was referenced before being defined
- Would cause `NameError: name 'flags' is not defined` at runtime

### Fix
- **Line 1065**: Initialize `flags = {}` at the start of `categorize_email()` function
- Prevents runtime errors and ensures all flag tracking works correctly

---

## 2. Increased Block Threshold

### Change
- **Line 485**: `MIN_BLOCK_SCORE` changed from `40` to `50`
- **Impact**: Emails need 25% higher spam score before being blocked
- **Reason**: Previous threshold was too low, causing legitimate emails to be blocked

### Code
```python
# OLD: MIN_BLOCK_SCORE = 40
# NEW: MIN_BLOCK_SCORE = 50
MIN_BLOCK_SCORE = int(os.getenv("MIN_BLOCK_SCORE", "50"))
```

---

## 3. Trusted Domain System

### New Feature
- **Lines 570-581**: Added `TRUSTED_DOMAINS` set with 30+ trusted companies
- Includes: Microsoft, Google, Apple, banks, payment processors, major services
- **Lines 1115-1121**: Trusted domains get -25 point bonus (reduces spam score)

### Impact
- Legitimate emails from trusted companies are less likely to be flagged
- Marketing emails from trusted domains get reduced penalties
- Bayesian spam detection is skipped for trusted domains

### Code
```python
# Trusted domains get -25 point bonus
if trusted in sender_dom:
    is_trusted_domain = True
    contributions.append(("trusted_domain_bonus", -25))
```

---

## 4. Business Spam Detection - Less Aggressive

### Change
- **OLD**: Flagged any business spam with score >= 10
- **NEW**: Only flags if:
  - Very high confidence (biz_score >= 20), OR
  - Medium confidence (biz_score >= 10) AND from free email AND not trusted

### Impact
- Legitimate business emails from corporate domains no longer flagged
- Only unsolicited business spam from free email accounts gets penalized
- Prevents false positives from legitimate B2B outreach

### Code
```python
# Lines 1160-1177
if biz_score >= 20:  # Very high - flag regardless
    contributions.append(("business_spam", biz_score))
elif biz_score >= 10 and is_free_email and not is_trusted_domain:
    # Medium confidence + free email = likely spam
    contributions.append(("business_spam", biz_score))
```

---

## 5. Marketing Email Penalties - Reduced for Trusted Domains

### Changes
- **Heavy marketing** (3+ matches): 30 → 20 points for trusted domains (33% reduction)
- **Regular marketing** (2+ matches): 15 → 8 points for trusted domains (47% reduction)
- **Marketing detection**: Skipped entirely for trusted domains

### Impact
- Legitimate marketing emails from trusted companies are less penalized
- Still flags aggressive marketing from unknown senders
- Prevents false positives from newsletters and promotional emails

### Code
```python
# Lines 1179-1195
if junk_matches >= 3:
    penalty = 20 if is_trusted_domain else 30  # 33% reduction
elif junk_matches >= 2:
    penalty = 8 if is_trusted_domain else 15    # 47% reduction

# Skip marketing detection for trusted domains
if not is_trusted_domain:
    marketing_contributions = detect_marketing_email(body, subject)
```

---

## 6. Generic Greeting Penalty - Reduced for Trusted Domains

### Change
- **OLD**: 10 points for all generic greetings
- **NEW**: 5 points for trusted domains, 10 for others

### Impact
- Legitimate mass emails from trusted companies less penalized
- Still flags generic greetings from unknown senders

### Code
```python
# Line 1223-1225
penalty = 5 if is_trusted_domain else 10
contributions.append(("generic_greeting", penalty))
```

---

## 7. Whitelist Effectiveness - Improved

### Change
- **OLD**: Complex calculation that didn't work well
- **NEW**: Simple reduction of up to 40 points for whitelisted senders

### Impact
- Whitelisted senders are much less likely to be flagged
- Safety check: Doesn't reduce if score > 70 (real threats still detected)

### Code
```python
# Lines 1240-1250
if is_wl and score < 70:
    score_reduction = min(score, 40)  # Up to 40 point reduction
    score = max(0, score - score_reduction)
```

---

## 8. Caution Threshold - Increased

### Change
- **OLD**: Caution verdict at score >= 15
- **NEW**: Caution verdict at score >= 20

### Impact
- Better separation between safe and suspicious emails
- Reduces false positives in the "caution" category

### Code
```python
# Line 1261
elif score >= 20:  # Increased from 15
    verdict = "caution"
```

---

## 9. Score Clamping

### Change
- **Line 1238**: Added `score = max(0, score)` to prevent negative scores
- Trusted domain bonus (-25) could make score negative

### Impact
- Prevents negative spam scores
- Ensures scores are always 0-100 range

---

## 10. Flags Dictionary Enhancement

### Change
- **Lines 1286-1290**: Added comprehensive flag tracking
- Includes: `is_trusted_domain`, `tracking_hit`, `bad_tld_hit`, etc.

### Impact
- Better debugging and analytics
- Can track which features triggered for each email

---

## Summary of Impact

### False Positives Reduced By:
1. **Trusted domains**: -25 point bonus + reduced penalties
2. **Higher thresholds**: 40 → 50 for block, 15 → 20 for caution
3. **Business spam**: Only flags with high confidence or free email
4. **Marketing**: 30-50% penalty reduction for trusted domains
5. **Whitelist**: Up to 40 point reduction (much more effective)

### Spam Detection Maintained:
- Phishing detection unchanged (still very sensitive)
- Malicious URL detection unchanged
- Suspicious TLD detection unchanged
- High-risk emails still blocked appropriately

---

## Testing Recommendations

1. Test emails from trusted domains (Microsoft, Google, banks)
2. Test legitimate business emails from corporate domains
3. Test marketing emails from known companies
4. Verify whitelisted senders are not flagged
5. Ensure real spam/phishing still gets blocked

---

## Configuration

All thresholds can be adjusted via environment variables:
- `MIN_BLOCK_SCORE`: Default 50 (was 40)
- `MIN_CONFIDENCE`: Default 0.00
- `STRICT_BAD_TLD`: Default True

Trusted domains list can be extended in `TRUSTED_DOMAINS` set (lines 570-581).

