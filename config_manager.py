"""
Configuration Manager for SOC Dashboard
Stores settings in SQLite with Fernet encryption for secrets.
DB config takes precedence over .env values.
"""

import os
import sqlite3
from datetime import datetime
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
_FHS_ENV = '/etc/soc-dashboard/.env'
if os.path.isfile(_FHS_ENV):
    load_dotenv(_FHS_ENV)

# Keys that contain secrets and must be encrypted in the DB
SECRET_KEYS = frozenset({
    'CLIENT_SECRET',
    'VIRUSTOTAL_API_KEY',
    'TALOS_API_KEY',
    'ABUSEIPDB_API_KEY',
    'SECRET_KEY',
    'TEAMS_WEBHOOK_URL',
    'COPILOT_WEBHOOK_SECRET',
})

# All configurable keys (shown on settings page)
CONFIGURABLE_KEYS = [
    # API Credentials
    'CLIENT_ID',
    'CLIENT_SECRET',
    'TENANT_ID',
    # Sentinel
    'SENTINEL_WORKSPACE_ID',
    'SENTINEL_WORKSPACE_NAME',
    # Threat Intel
    'VIRUSTOTAL_API_KEY',
    'TALOS_API_KEY',
    'ABUSEIPDB_API_KEY',
    # Operational
    'REFRESH_INTERVAL_MINUTES',
    'INCIDENTS_DISPLAY_LIMIT',
    # Access Control
    'ADMIN_USERS',
    # Escalation
    'ESCALATION_EMAIL',
    'TEAMS_CHANNEL_ID',
    'TEAMS_WEBHOOK_URL',
    'ESCALATION_METHODS',
    # AI & Data Lake
    'FOUNDRY_ENDPOINT',
    'FOUNDRY_DEPLOYMENT',
    'FOUNDRY_PROJECT_ENDPOINT',
    'FOUNDRY_AGENT_NAME',
    # Feature Toggles (values: 'true' / 'false')
    'AI_ASSISTANT_ENABLED',
    'KQL_CONSOLE_ENABLED',
    'MDTI_ENABLED',
    'AI_AUTO_ENRICH_ENABLED',
    'AI_AUTO_COMMENT_ENABLED',
    'CLOSE_INCIDENT_ENABLED',
    'LOGS_ENABLED',
    'IOC_UPLOAD_ENABLED',
    'VIRUSTOTAL_ENABLED',
    'SECURITY_COPILOT_ENABLED',
    'COPILOT_AUTO_ENRICH_ENABLED',
    'COPILOT_AUTO_ENRICH_MAX_PER_CYCLE',
    'COPILOT_WEBHOOK_SECRET',
    # Autonomous Triage & Response
    'TRIAGE_ENABLED',
    'TRIAGE_AUTO_COMMENT_ENABLED',
    'TRIAGE_ROUTING_MODE',
    'FOUNDRY_DEPLOYMENT_FAST',
    'FOUNDRY_DEPLOYMENT_DEEP',
    'TRIAGE_MAX_PER_CYCLE',
    'TRIAGE_BASELINE_DAYS',
    'TRIAGE_EVIDENCE_PACK_ENABLED',
    'TRIAGE_QUERY_DIR',
    'TRIAGE_MIN_CONFIDENCE_FOR_ACTIONS',
    'TRIAGE_PARTIAL_CONFIDENCE_CAP',
    'TRIAGE_AUTO_CLOSE_FP_ENABLED',
    'TRIAGE_AUTO_CLOSE_MIN_CONFIDENCE',
    'RESPONSE_ACTIONS_ENABLED',
    'RESPONSE_DRY_RUN',
    'RESPONSE_ALLOW_ISOLATE_DEVICE',
    'RESPONSE_ALLOW_REVOKE_SESSIONS',
    'RESPONSE_ALLOW_DISABLE_ACCOUNT',
    'RESPONSE_ALLOW_PUSH_IOC',
    'RESPONSE_ALLOW_CLOSE_FP',
    'RESPONSE_ISOLATION_TYPE',
    'RESPONSE_IOC_CONFIDENCE',
    'RESPONSE_FP_DETERMINATION',
]


def _get_db_path() -> str:
    return os.getenv('DB_PATH', 'soc_dashboard.db')


def _get_key_path() -> str:
    return os.getenv('CONFIG_KEY_PATH',
                     os.path.join(os.path.dirname(_get_db_path()), '.encryption_key'))


def _load_or_create_key() -> bytes:
    """Load the Fernet key from disk, or create one on first run."""
    key_path = _get_key_path()
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            return f.read().strip()
    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(key_path) or '.', exist_ok=True)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(key)
    print(f"🔑 Generated new encryption key at {key_path}")
    return key


_fernet = None

def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_or_create_key())
    return _fernet


def _encrypt(value: str) -> str:
    return _get_fernet().encrypt(value.encode()).decode()


def _decrypt(token: str) -> str:
    return _get_fernet().decrypt(token.encode()).decode()


def _ensure_table() -> None:
    """Create the config table if it doesn't exist yet."""
    conn = sqlite3.connect(_get_db_path())
    conn.execute(
        'CREATE TABLE IF NOT EXISTS config ('
        '  key TEXT PRIMARY KEY,'
        '  value TEXT,'
        '  is_encrypted INTEGER DEFAULT 0,'
        '  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP'
        ')'
    )
    conn.commit()
    conn.close()
    _migrate_encryption()  # re-save values whose secret status changed


def _migrate_encryption() -> None:
    """Re-encrypt or decrypt values whose SECRET_KEYS membership changed."""
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute('SELECT key, value, is_encrypted FROM config')
    for row in cur.fetchall():
        key, val, is_enc = row['key'], row['value'], row['is_encrypted']
        should_enc = key in SECRET_KEYS
        if is_enc and not should_enc and val:
            try:
                plain = _decrypt(val)
                conn.execute(
                    'UPDATE config SET value=?, is_encrypted=0, updated_at=? WHERE key=?',
                    (plain, datetime.now().isoformat(), key)
                )
                print(f'🔑 Migrated {key}: encrypted → plaintext')
            except Exception:
                pass  # value may already be plaintext despite flag
        elif not is_enc and should_enc and val:
            try:
                enc = _encrypt(val)
                conn.execute(
                    'UPDATE config SET value=?, is_encrypted=1, updated_at=? WHERE key=?',
                    (enc, datetime.now().isoformat(), key)
                )
                print(f'🔑 Migrated {key}: plaintext → encrypted')
            except Exception:
                pass
    conn.commit()
    conn.close()


# ── CRUD ────────────────────────────────────────

def get_config(key: str, default: str | None = None) -> str | None:
    """
    Get a config value.  Priority: DB → os.environ → default.
    Decrypts transparently if the value is stored encrypted.
    """
    try:
        _ensure_table()
        conn = sqlite3.connect(_get_db_path())
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute('SELECT value, is_encrypted FROM config WHERE key = ?', (key,))
        row = cur.fetchone()
        conn.close()
        if row and row['value']:
            val = row['value']
            if row['is_encrypted']:
                val = _decrypt(val)
            return val
    except Exception:
        pass

    env_val = os.getenv(key, '').strip()
    return env_val if env_val else default


def set_config(key: str, value: str, encrypt: bool | None = None) -> None:
    """
    Upsert a config value.  If *encrypt* is None, auto-detect from SECRET_KEYS.
    """
    if encrypt is None:
        encrypt = key in SECRET_KEYS

    stored = _encrypt(value) if encrypt else value
    is_enc = 1 if encrypt else 0

    _ensure_table()
    conn = sqlite3.connect(_get_db_path())
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO config (key, value, is_encrypted, updated_at) '
        'VALUES (?, ?, ?, ?) '
        'ON CONFLICT(key) DO UPDATE SET value=excluded.value, '
        'is_encrypted=excluded.is_encrypted, updated_at=excluded.updated_at',
        (key, stored, is_enc, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def get_all_config() -> list[dict]:
    """
    Return all configurable keys with their values.
    Secret values are masked as '••••••••'.
    """
    result = []
    for key in CONFIGURABLE_KEYS:
        raw = get_config(key)
        is_secret = key in SECRET_KEYS
        result.append({
            'key': key,
            'value': '••••••••' if (is_secret and raw) else (raw or ''),
            'hasValue': bool(raw),
            'isSecret': is_secret,
        })
    return result


def delete_config(key: str) -> None:
    conn = sqlite3.connect(_get_db_path())
    cur = conn.cursor()
    cur.execute('DELETE FROM config WHERE key = ?', (key,))
    conn.commit()
    conn.close()
