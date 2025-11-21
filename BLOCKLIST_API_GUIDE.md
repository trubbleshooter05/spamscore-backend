# Blocklist API Endpoints - Quick Reference

The blocklist feature allows users to permanently block emails from specific senders or domains.

---

## 📋 Available Endpoints

### 1. Get Blocklist
Retrieve all blocked entries for a user.

```http
GET /api/blocklist/list?user_email=user@example.com
```

**Query Parameters:**
- `user_email` (required) - User's email address

**Response:**
```json
{
  "blocklist": [
    {
      "type": "email",
      "value": "spam@example.com",
      "added_at": "2025-11-20T10:30:00Z"
    },
    {
      "type": "domain",
      "value": "spammydomain.com",
      "added_at": "2025-11-20T11:00:00Z"
    }
  ]
}
```

---

### 2. Add to Blocklist
Block an email address or domain.

```http
POST /api/blocklist/add
Content-Type: application/json

{
  "user_email": "user@example.com",
  "type": "email",  // or "domain"
  "value": "spam@example.com"
}
```

**Request Body:**
- `user_email` (required) - User's email address
- `type` (required) - Either "email" or "domain"
- `value` (required) - The email or domain to block

**Response (Success):**
```json
{
  "success": true,
  "message": "Added spam@example.com to blocklist"
}
```

**Response (Error - Invalid Email):**
```json
{
  "detail": "Invalid email format: not-an-email"
}
```

**Validation:**
- Email format validated (RFC 5322 basic)
- Domain format validated (no @ symbol, valid DNS format)
- Automatically removes from whitelist if conflict exists

---

### 3. Remove from Blocklist
Unblock an email address or domain.

```http
POST /api/blocklist/remove
Content-Type: application/json

{
  "user_email": "user@example.com",
  "type": "email",
  "value": "spam@example.com"
}
```

**Request Body:**
- `user_email` (required) - User's email address
- `type` (required) - Either "email" or "domain"
- `value` (required) - The email or domain to unblock

**Response (Success):**
```json
{
  "success": true,
  "message": "Removed spam@example.com from blocklist"
}
```

---

## 🔒 Validation Rules

### Email Validation
- Must be valid email format (e.g., `user@domain.com`)
- Maximum 254 characters
- Basic RFC 5322 compliance

### Domain Validation
- Must be valid domain format (e.g., `domain.com`)
- Cannot contain @ symbol
- Maximum 253 characters
- Must have valid DNS format

---

## 🤝 Interaction with Whitelist

**Important:** When adding an entry to the blocklist:
1. The system checks if it's already whitelisted
2. If yes, it's automatically removed from the whitelist
3. Then added to the blocklist

This ensures **blocklist always takes precedence** over whitelist.

---

## 💡 Usage Examples

### Example 1: Block a Spammer's Email
```bash
curl -X POST https://your-api.com/api/blocklist/add \
  -H "Content-Type: application/json" \
  -d '{
    "user_email": "me@example.com",
    "type": "email",
    "value": "spammer@spam.com"
  }'
```

### Example 2: Block an Entire Domain
```bash
curl -X POST https://your-api.com/api/blocklist/add \
  -H "Content-Type: application/json" \
  -d '{
    "user_email": "me@example.com",
    "type": "domain",
    "value": "spam-domain.xyz"
  }'
```

### Example 3: View All Blocked Entries
```bash
curl "https://your-api.com/api/blocklist/list?user_email=me@example.com"
```

### Example 4: Unblock an Email
```bash
curl -X POST https://your-api.com/api/blocklist/remove \
  -H "Content-Type: application/json" \
  -d '{
    "user_email": "me@example.com",
    "type": "email",
    "value": "spammer@spam.com"
  }'
```

---

## ⚠️ Error Responses

### 400 Bad Request
```json
{
  "detail": "Invalid email format: not-valid"
}
```

Causes:
- Invalid email format
- Invalid domain format
- Invalid type (must be 'email' or 'domain')

### 503 Service Unavailable
```json
{
  "detail": "Database not available"
}
```

Cause: Redis connection failed

### 500 Internal Server Error
```json
{
  "detail": "Failed to add to blocklist"
}
```

Cause: Database operation failed

---

## 🎯 Integration with Email Scanning

When an email is scanned:
1. System checks if sender is in blocklist
2. If **blocked**, email gets verdict: `"block"` with score: `100`
3. If **not blocked**, normal spam analysis proceeds
4. Blocklist check happens BEFORE whitelist check

**Priority Order:**
1. Blocklist (highest priority) → Auto-block
2. Whitelist → Auto-allow
3. Spam Analysis → Normal scoring

---

## 📊 Dashboard Integration

The blocklist endpoints are designed to work with the SpamScore dashboard:

**Dashboard URL:** https://spamscore-dashboard.vercel.app

Features:
- View all blocked senders
- Add emails/domains to blocklist
- Remove entries with one click
- See when each entry was added

---

## 🔐 Security Features

✅ **Input Validation** - All inputs validated before processing
✅ **Format Checking** - Email and domain formats verified
✅ **Length Limits** - Prevents buffer overflow attacks
✅ **Conflict Resolution** - Automatic whitelist/blocklist conflict handling
✅ **Error Handling** - Clear, secure error messages

---

## 📝 Notes

- **Storage:** Uses Redis Sets for O(1) lookup performance
- **Metadata:** Tracks when each entry was added
- **Expiry:** No expiry - entries persist until manually removed
- **Case Insensitive:** All emails/domains stored in lowercase

---

**Need Help?**
- Check main API docs: `GET /` endpoint
- Review IMPROVEMENTS_SUMMARY.md
- See README_SERVER_FILES.md for file structure
