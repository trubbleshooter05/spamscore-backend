# Server Files Documentation

## Active Files

- **api/index.py** - Main API server (ACTIVE)
  - Full-featured spam scoring API with Redis integration
  - Whitelist/blocklist management
  - User authentication and session management
  - Dashboard endpoints
  - Google Safe Browsing integration
  - **This is the primary entry point for the application**

## Deprecated Files

- **server.py.deprecated** - Old version (DEPRECATED)
  - Previous implementation without Redis features
  - Missing whitelist/blocklist functionality
  - No user management
  - **DO NOT USE - Kept for reference only**

- **server.py.bak** - Backup file (BACKUP)
  - Automatic backup created during development

## Which File to Use?

**Always use `api/index.py`** - it's the current, maintained version with all features.

The `server.py` files are deprecated and should not be used in production.
