# AGGRESSIVE MODE - Changes Summary

## Date: 2025-11-21

The system has been switched from **BALANCED MODE** (optimized for fewer false positives) to **AGGRESSIVE MODE** (optimized to catch more spam/marketing).

---

## 🎯 Changes Made

### 1. **Lowered Block Threshold**
```python
MIN_BLOCK_SCORE: 50 → 35 (-30%)
```
**Impact:** Marketing emails scoring 35-49 will now be **BLOCKED** instead of just **CAUTIONED**.

---

### 2. **Increased Marketing Detection Scores**

| Detection Type | Old Score | New Score | Increase |
|----------------|-----------|-----------|----------|
| List-Unsubscribe header | 35 | 40 | +14% |
| Multiple urgency tactics (2+) | 25 | 35 | +40% |
| Single urgency tactic | 10 | 15 | +50% |
| Confirmed marketing spam | 30 | 40 | +33% |
| Multiple tracking URLs (3+) | 20 | 25 | +25% |
| Single tracking URL | 0 | 12 | NEW! |

**Impact:** Marketing emails will score **30-50% higher**, pushing them into BLOCK territory.

---

### 3. **Added Marketing Platform Detection**

New platforms detected with **+25 points each**:
- ✅ ClickFunnels (`clickfunnels`, `clickfunnelsnotifications.com`, `myclickfunnels.com`)
- ✅ HubSpot (`hubspot`, `hubspotlinks.com`, `hs-email.net`)
- ✅ Mailchimp (`mailchimp`, `list-manage.com`, `mailchi.mp`)
- ✅ SendGrid (`sendgrid.net`, `sendgrid.com`)
- ✅ Constant Contact (`constantcontact.com`)
- ✅ ActiveCampaign (`activecampaign.com`)
- ✅ ConvertKit (`convertkit.com`)
- ✅ Drip (`drip.com`, `getdrip.com`)
- ✅ AWeber (`aweber.com`)
- ✅ Infusionsoft/Keap (`infusionsoft.com`, `keap.com`)

**Impact:** Any email sent through these marketing platforms gets **+25 points** automatically.

---

### 4. **More Aggressive Verdict Thresholds**

| Score Range | Old Verdict | New Verdict |
|-------------|-------------|-------------|
| 50+ | BLOCK | BLOCK |
| 35-49 | CAUTION | **BLOCK** ⬆️ |
| 20-34 | CAUTION | CAUTION |
| 15-19 | SAFE | **CAUTION** ⬆️ |
| 0-14 | SAFE | SAFE |

**Impact:** More emails will be blocked or cautioned.

---

### 5. **Enhanced Marketing Signal Detection**

```python
# Lowered junk threshold from 3 to 2
junk_matches >= 2  # Was: >= 3
```

**Impact:** Emails with just 2 marketing keywords (e.g., "unsubscribe" + "limited time") will trigger marketing detection.

---

## 📊 Expected Results

### Before AGGRESSIVE MODE:
**ClickFunnels Example Email:**
- Score: ~30 points
- Verdict: ⚠️ CAUTION
- Category: marketing
- **Result:** Not blocked ❌

### After AGGRESSIVE MODE:
**ClickFunnels Example Email:**
- ClickFunnels platform detected: **+25 points**
- Unsubscribe link: **+40 points** (was 35)
- Urgency tactics ("TODAY!", "NOW"): **+35 points** (was 25)
- Tracking URLs: **+25 points** (was 20)
- Confirmed marketing: **+40 points** (was 30)
- **Total: ~165 points**
- Verdict: 🚫 **BLOCK**
- Category: marketing
- **Result:** BLOCKED ✅

---

## 🎯 Coverage Improvements

**Marketing Platforms Now Detected:**
- Email marketing services (10 platforms)
- Newsletter services
- Sales automation tools
- CRM marketing features

**Marketing Indicators Now More Aggressive:**
- Unsubscribe links: +14% scoring
- Urgency tactics: +40-50% scoring
- Tracking URLs: +25% scoring
- Platform detection: NEW +25 points

---

## ⚠️ Potential Side Effects

### Minimal Risk:
- **Legitimate marketing you want** might be blocked
- **Solution:** Use the whitelist feature for trusted senders

### Very Low Risk:
- **Transactional emails** from marketing platforms (receipts, confirmations) might score higher
- **Mitigation:** Already have checks for transactional keywords like "receipt", "confirmation", "invoice"

---

## 🔧 Fine-Tuning Options

If you experience issues, you can adjust:

### Option 1: Slightly Less Aggressive
```bash
# Set via environment variable
MIN_BLOCK_SCORE=40  # Instead of 35
```

### Option 2: Whitelist Specific Platforms
```bash
# Example: Whitelist ClickFunnels if you use it
curl -X POST https://YOUR_API/api/whitelist/add \
  -d '{"user_email": "you@example.com", "type": "domain", "value": "clickfunnelsnotifications.com"}'
```

### Option 3: Nuclear Mode (Catch Everything)
```bash
MIN_BLOCK_SCORE=25  # Extremely aggressive
```

---

## 📈 Monitoring

After deployment, monitor for:
1. **Reduction in false negatives** (spam getting through)
2. **Any increase in false positives** (legitimate emails blocked)
3. **User feedback** on blocking effectiveness

---

## 🚀 Deployment

**Version:** 2.3-aggressive-mode
**Build:** Automatic on next deploy
**Rollback:** Change MIN_BLOCK_SCORE back to 50 in `api/index.py` line 485

---

**Status:** ✅ Ready to deploy
