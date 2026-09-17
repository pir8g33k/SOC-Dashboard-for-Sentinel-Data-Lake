"""
SOC Dashboard Backend - Serves data from SQLite database with timeline filtering
"""
from flask import Flask, jsonify, redirect, send_file, send_from_directory, request, session
from flask_cors import CORS
from flask_session import Session
from datetime import datetime, timedelta
import json
import os
import secrets
import threading

# Import database functions
try:
    from database import (
        get_incidents,
        get_alerts,
        get_metrics_summary,
        get_latest_threat_intel,
        get_database_stats,
        init_database,
        update_incident_field,
        create_case, get_cases, get_case, update_case, delete_case,
        save_attack_story, get_attack_story,
        get_workspaces, add_workspace, remove_workspace, set_default_workspace,
        insert_enrichment, get_enrichment, get_enrichments_batch, get_enrichment_stats,
    )
    from fetch_live_data import (
        fetch_secure_score, calculate_daily_alert_volume, get_last_incident_source,
        graph_patch_incident, graph_post_comment, graph_send_mail,
        send_teams_channel_escalation,
        send_teams_webhook_escalation,
    )
    DB_AVAILABLE = True
    init_database()
    from triage_db import init_triage_schema
    init_triage_schema()
except ImportError:
    print("⚠️  Database module not available, falling back to JSON mode")
    DB_AVAILABLE = False


def _detect_incident_source(incidents: list) -> str:
    """Detect data source from incident characteristics.
    Graph incidents have numeric IDs; Sentinel have GUIDs; demo have 'INC-' prefix."""
    if not incidents:
        return 'none'
    sample_id = str(incidents[0].get('id', ''))
    if sample_id.isdigit():
        return 'microsoft_graph_api'
    if sample_id.startswith('INC-') or sample_id.startswith('DEMO'):
        return 'demo'
    return 'sentinel_kql'

from auth import (
    require_login,
    require_admin,
    initiate_login,
    handle_callback,
    handle_logout,
    get_current_user,
    get_user_token,
    get_user_sentinel_token,
    get_user_triage_token,
)
from config_manager import get_config, set_config, get_all_config

# ── First-run setup detection ───────────────────

_PLACEHOLDER_PATTERNS = ('your-', 'change-me', 'yourdomain', 'placeholder')

def _needs_setup() -> bool:
    """True when essential Entra ID config is missing or still has placeholder values."""
    for key in ('TENANT_ID', 'CLIENT_ID', 'CLIENT_SECRET'):
        val = get_config(key) or ''
        if not val or any(p in val.lower() for p in _PLACEHOLDER_PATTERNS):
            return True
    return False

app = Flask(__name__)

# Wire Flask logger to gunicorn's logger when running under gunicorn
import logging as _logging
_gunicorn_logger = _logging.getLogger('gunicorn.error')
if _gunicorn_logger.handlers:
    app.logger.handlers = _gunicorn_logger.handlers
    app.logger.setLevel(_gunicorn_logger.level)

# Session config
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(
    os.getenv('DB_PATH', 'soc_dashboard.db').rsplit(os.sep, 1)[0] or '.',
    'flask_sessions',
)
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') != 'development'
Session(app)

cors_origins = os.getenv('CORS_ORIGINS', 'http://localhost:5000,http://127.0.0.1:5000')
CORS(app, origins=[o.strip() for o in cors_origins.split(',')])

# Autonomous triage + gated response actions
from routes_triage import triage_bp
app.register_blueprint(triage_bp)

@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self' https://api.loganalytics.io; "
        "form-action 'self' https://login.microsoftonline.com"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    return send_from_directory(os.path.join(app.root_path, 'static'),
                             'favicon.svg', mimetype='image/svg+xml')

# ── First-run setup routes ──────────────────────

_SETUP_PATHS = frozenset({'/setup', '/api/setup', '/api/setup/test-connection', '/favicon.ico'})

@app.before_request
def _check_setup_needed():
    """Redirect everything to the setup page until Entra creds are configured."""
    if request.path in _SETUP_PATHS:
        return None
    if _needs_setup():
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Initial setup required', 'setup_url': '/setup'}), 503
        return redirect('/setup')
    return None


@app.route('/setup')
def setup_page():
    """Serve the first-run setup wizard."""
    if not _needs_setup():
        return redirect('/login')
    return send_file('setup.html')


@app.route('/api/setup', methods=['POST'])
def save_setup():
    """Save initial configuration (only works while setup is needed)."""
    if not _needs_setup():
        return jsonify({'error': 'Setup already complete'}), 403
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({'error': 'Missing JSON payload'}), 400
    SETUP_KEYS = {
        'TENANT_ID', 'CLIENT_ID', 'CLIENT_SECRET',
        'REDIRECT_URI', 'ADMIN_USERS', 'ESCALATION_EMAIL',
        'AZURE_SUBSCRIPTION_ID', 'AZURE_RESOURCE_GROUP',
        'SENTINEL_WORKSPACE_ID', 'SENTINEL_WORKSPACE_NAME',
    }
    saved = []
    for key, value in payload.items():
        if key in SETUP_KEYS and isinstance(value, str) and value.strip():
            set_config(key, value.strip())
            saved.append(key)
    # Seed workspaces table from setup values
    if 'SENTINEL_WORKSPACE_ID' in saved:
        try:
            ws_id = payload['SENTINEL_WORKSPACE_ID'].strip()
            ws_name = (payload.get('SENTINEL_WORKSPACE_NAME') or 'Default').strip()
            existing = get_workspaces()
            if not any(w['workspace_id'] == ws_id for w in existing):
                add_workspace(ws_id, ws_name, is_default=True)
        except Exception:
            pass
    print(f'\u2699\ufe0f  Setup: saved {saved}')
    return jsonify({'success': True, 'saved': saved})


@app.route('/api/setup/test-connection', methods=['POST'])
def setup_test_connection():
    """Test Graph API connectivity with credentials from the request body (pre-save)."""
    if not _needs_setup():
        return jsonify({'error': 'Setup already complete'}), 403
    payload = request.get_json(silent=True) or {}
    client_id = (payload.get('CLIENT_ID') or '').strip()
    client_secret = (payload.get('CLIENT_SECRET') or '').strip()
    tenant_id = (payload.get('TENANT_ID') or '').strip()
    if not all([client_id, client_secret, tenant_id]):
        return jsonify({'success': False, 'message': 'Tenant ID, Client ID, and Client Secret are required.'})
    try:
        import requests as http
        token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
        resp = http.post(token_url, data={
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': 'https://graph.microsoft.com/.default',
            'grant_type': 'client_credentials',
        }, timeout=10)
        if resp.status_code == 200:
            return jsonify({'success': True, 'message': 'Connection successful \u2014 Graph API token acquired.'})
        err = resp.json().get('error_description', f'HTTP {resp.status_code}')
        return jsonify({'success': False, 'message': f'Token request failed: {err}'})
    except Exception:
        return jsonify({'success': False, 'message': 'Connection failed \u2014 check network and credentials.'})


# ── Auth routes (unauthenticated) ────────────────

@app.route('/login')
def login():
    return initiate_login()

@app.route('/auth/callback')
def auth_callback():
    return handle_callback()

@app.route('/logout')
def logout():
    return handle_logout()

@app.route('/logged-out')
def logged_out():
    return """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Signed out - SOC Dashboard</title>
    <style>
        body { margin: 0; min-height: 100vh; display: grid; place-items: center; font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f7fb; color: #1f2937; }
        main { width: min(420px, calc(100vw - 32px)); padding: 28px; background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08); }
        h1 { margin: 0 0 10px; font-size: 24px; }
        p { margin: 0 0 22px; color: #4b5563; line-height: 1.5; }
        a { display: inline-flex; align-items: center; min-height: 40px; padding: 0 16px; border-radius: 6px; background: #1565c0; color: #fff; text-decoration: none; font-weight: 600; }
        a:hover { background: #0d47a1; }
    </style>
</head>
<body>
    <main>
        <h1>Signed out</h1>
        <p>Your dashboard session has been closed. Use the button below when you are ready to sign in again.</p>
        <a href="/login">Sign in</a>
    </main>
</body>
</html>
"""

@app.route('/api/me')
@require_login
def me():
    return get_current_user()

# ── Settings API (admin-only) ───────────────────

@app.route('/api/settings', methods=['GET'])
@require_admin
def get_settings():
    """Return all configurable settings (secrets masked)."""
    items = get_all_config()
    flat = {item['key']: item['value'] for item in items}
    return jsonify(flat)

@app.route('/api/settings', methods=['PUT'])
@require_admin
def update_settings():
    """Update one or more settings. Expects flat {key: value} JSON."""
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({'error': 'Missing JSON payload'}), 400

    ALLOWED = {
        'CLIENT_ID', 'CLIENT_SECRET', 'TENANT_ID',
        'SENTINEL_WORKSPACE_ID', 'SENTINEL_WORKSPACE_NAME',
        'VIRUSTOTAL_API_KEY', 'TALOS_API_KEY', 'ABUSEIPDB_API_KEY',
        'REFRESH_INTERVAL_MINUTES', 'INCIDENTS_DISPLAY_LIMIT', 'ESCALATION_EMAIL',
        'TEAMS_CHANNEL_ID', 'TEAMS_WEBHOOK_URL', 'ESCALATION_METHODS',
        'FOUNDRY_ENDPOINT', 'FOUNDRY_DEPLOYMENT',
        'FOUNDRY_PROJECT_ENDPOINT', 'FOUNDRY_AGENT_NAME',
        'AI_ASSISTANT_ENABLED', 'KQL_CONSOLE_ENABLED',
        'MDTI_ENABLED',
        'AI_AUTO_ENRICH_ENABLED', 'AI_AUTO_COMMENT_ENABLED',
        'CLOSE_INCIDENT_ENABLED',
        'LOGS_ENABLED',
        'IOC_UPLOAD_ENABLED',
        'VIRUSTOTAL_ENABLED',
        'SECURITY_COPILOT_ENABLED',
        'COPILOT_AUTO_ENRICH_ENABLED',
        'COPILOT_AUTO_ENRICH_MAX_PER_CYCLE',
        'COPILOT_WEBHOOK_SECRET',
        # Autonomous triage
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
        # Gated response actions
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
    }
    updated = []
    for key, value in payload.items():
        if key not in ALLOWED:
            continue
        if value == '••••••••':
            continue
        set_config(key, str(value))
        updated.append(key)

    return jsonify({'updated': updated})

@app.route('/api/settings/test-connection', methods=['POST'])
@require_admin
def test_connection():
    """Test Graph API connectivity with current config."""
    try:
        import requests as http
        from config_manager import get_config as cfg
        client_id = cfg('CLIENT_ID')
        client_secret = cfg('CLIENT_SECRET')
        tenant_id = cfg('TENANT_ID')
        if not all([client_id, client_secret, tenant_id]):
            return jsonify({'success': False, 'message': 'Missing CLIENT_ID, CLIENT_SECRET, or TENANT_ID'})
        token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
        resp = http.post(token_url, data={
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': 'https://graph.microsoft.com/.default',
            'grant_type': 'client_credentials',
        }, timeout=10)
        if resp.status_code == 200:
            return jsonify({'success': True, 'message': 'Graph API connection successful'})
        return jsonify({'success': False, 'message': f'Token request failed: HTTP {resp.status_code}'})
    except Exception:
        return jsonify({'success': False, 'message': 'Connection test failed — check network and credentials'})

_refresh_status = {'running': False, 'last_result': None, 'last_error': None, 'started_at': None, 'finished_at': None}

@app.route('/api/refresh', methods=['POST'])
@require_admin
def trigger_refresh():
    """Trigger an immediate data refresh (runs in background thread)."""
    if _refresh_status['running']:
        return jsonify({'success': False, 'message': 'Refresh already in progress'}), 409

    def _run_refresh():
        _refresh_status['running'] = True
        _refresh_status['last_error'] = None
        _refresh_status['started_at'] = datetime.utcnow().isoformat()
        _refresh_status['finished_at'] = None
        try:
            from append_data import fetch_and_append_new_data
            result = fetch_and_append_new_data()
            _refresh_status['last_result'] = result
        except Exception as exc:
            _refresh_status['last_error'] = type(exc).__name__
            app.logger.error('Refresh failed: %s', exc)
        finally:
            _refresh_status['running'] = False
            _refresh_status['finished_at'] = datetime.utcnow().isoformat()

    threading.Thread(target=_run_refresh, daemon=True).start()
    return jsonify({'success': True, 'message': 'Refresh started — data will update shortly'})

@app.route('/api/refresh/status')
@require_login
def refresh_status():
    """Poll the background refresh status."""
    return jsonify(_refresh_status)

# ── Dashboard routes (authenticated) ────────────

@app.route('/api/dashboard-data', methods=['GET'])
@require_login
def get_dashboard_data():
    """
    Serve dashboard data from SQLite database with filtering
    
    Query Parameters:
        days: Get data from last N days (e.g., ?days=7)
        start_date: ISO format start date (e.g., ?start_date=2026-01-01)
        end_date: ISO format end date (e.g., ?end_date=2026-02-03)
        severity: Filter by severity (e.g., ?severity=High)
        status: Filter by status (e.g., ?status=Active)
    """
    
    # Use database if available, otherwise fall back to JSON
    if DB_AVAILABLE:
        return get_dashboard_data_from_db()
    else:
        return get_dashboard_data_from_json()

def get_dashboard_data_from_db():
    """Get dashboard data from SQLite database with filtering"""
    try:
        # Get query parameters
        days = request.args.get('days', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        severity = request.args.get('severity')
        status = request.args.get('status')
        
        # Default to last 30 days if no filter specified
        if not any([days, start_date, end_date]):
            days = 30
        
        print(f"\n📊 Querying database with filters:")
        if days:
            print(f"   • Last {days} days")
        if start_date:
            print(f"   • Start date: {start_date}")
        if end_date:
            print(f"   • End date: {end_date}")
        if severity:
            print(f"   • Severity: {severity}")
        if status:
            print(f"   • Status: {status}")
        
        # Query incidents
        incidents = get_incidents(
            days=days,
            start_date=start_date,
            end_date=end_date,
            severity=severity,
            status=status
        )
        
        # Get alerts for the filtered incidents
        incident_ids = [inc.get('id') for inc in incidents]
        alerts = get_alerts(days=days, start_date=start_date, end_date=end_date)
        
        # Filter alerts to only those related to our incidents
        alerts = [a for a in alerts if a.get('incidentId') in incident_ids]
        
        # Get metrics for the filtered period
        metrics_days = days if days else 30
        metrics = get_metrics_summary(days=metrics_days)
        
        # Get latest threat intelligence
        threat_intel_data = get_latest_threat_intel()
        threat_intel = threat_intel_data.get('data', {}) if threat_intel_data else {}
        
        # Get secure score (always latest)
        secure_score_data = fetch_secure_score()
        
        # Calculate daily alert volume
        daily_alerts = calculate_daily_alert_volume(alerts)
        
        # Build response
        refresh_interval = int(get_config('REFRESH_INTERVAL_MINUTES', '60') or '60')
        try:
            incidents_display_limit = int(get_config('INCIDENTS_DISPLAY_LIMIT', '100') or '100')
        except (TypeError, ValueError):
            incidents_display_limit = 100
        incidents_display_limit = max(10, min(1000, incidents_display_limit))
        data = {
            'timestamp': datetime.now().isoformat(),
            'dataSource': 'sqlite_database',
            'refreshInterval': refresh_interval,
            'incidentsDisplayLimit': incidents_display_limit,
            'filters': {
                'days': days,
                'start_date': start_date,
                'end_date': end_date,
                'severity': severity,
                'status': status
            },
            'secureScore': {
                'current': secure_score_data.get('percentage', 0),
                'max': 100,
                'trend': secure_score_data.get('trend', 0),
                'isDemo': secure_score_data.get('source') not in ('microsoft_graph_api',),
                'rawScore': secure_score_data.get('currentScore'),
                'maxPossible': secure_score_data.get('maxScore'),
                'controlScores': secure_score_data.get('controlScores', []),
                'categoryScores': secure_score_data.get('categoryScores', []),
                'recommendations': secure_score_data.get('recommendations', []),
                'recommendationsByCategory': secure_score_data.get('recommendationsByCategory', {}),
                'recentImprovements': secure_score_data.get('recentImprovements', []),
                'actionCounts': secure_score_data.get('actionCounts', {}),
                'history': secure_score_data.get('history', []),
            },
            'incidents': incidents,
            'enrichments': _get_enrichment_previews(incident_ids),
            'alerts': alerts,
            'metrics': metrics,
            'incidentSource': _detect_incident_source(incidents),
            'secureScoreTrend': secure_score_data.get('history', []),
            'dailyAlerts': daily_alerts,
            'threatIntelligence': threat_intel
        }
        
        print(f"✅ Serving {len(incidents)} incidents and {len(alerts)} alerts from database")
        return jsonify(data)
        
    except Exception as e:
        print(f"❌ Error querying database: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Database query failed',
            'message': 'An internal error occurred. Check server logs for details.'
        }), 500

def get_dashboard_data_from_json():
    """Fallback: Get dashboard data from JSON file"""
    try:
        _db_dir = os.path.dirname(os.getenv('DB_PATH', 'soc_dashboard.db')) or '.'
        data_file = os.path.join(_db_dir, 'dashboard_data.json')
        
        # Check if data file exists
        if not os.path.exists(data_file):
            return jsonify({
                'error': 'Dashboard data not found',
                'message': 'Please run "python migrate_json_to_db.py" to set up the database'
            }), 404
        
        # Read the pre-fetched data
        with open(data_file, 'r') as f:
            data = json.load(f)
        
        data['dataSource'] = 'json_file'
        print(f"✅ Serving dashboard data from {data_file} (fallback mode)")
        print(f"   📊 Last updated: {data.get('timestamp')}")
        print(f"   📊 {len(data.get('incidents', []))} incidents, {len(data.get('alerts', []))} alerts")
        print(f"   📊 Secure Score: {data.get('secureScore', {}).get('current')}%")
        
        return jsonify(data)
        
    except json.JSONDecodeError as e:
        print(f"❌ JSON decode error in dashboard_data.json: {e}")
        return jsonify({
            'error': 'Invalid data file',
            'message': 'Failed to parse data file. Check server logs for details.'
        }), 500
    except Exception as e:
        print(f"❌ Error serving dashboard data: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Server error',
            'message': 'An internal error occurred. Check server logs for details.'
        }), 500

@app.route('/api/database-stats', methods=['GET'])
@require_login
def get_db_stats():
    """Get database statistics"""
    if not DB_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        stats = get_database_stats()
        return jsonify(stats)
    except Exception as e:
        print(f"❌ Database stats error: {e}")
        return jsonify({'error': 'Failed to retrieve database statistics'}), 500

# ── Incident action routes (authenticated) ─────

@app.route('/api/incidents/<incident_id>/assign', methods=['POST'])
@require_login
def assign_incident(incident_id):
    """Assign a Graph Security incident to the logged-in user."""
    user = session.get('user', {})
    email = user.get('email', '')
    name = user.get('name', email)
    oid = user.get('oid', '')
    if not email:
        return jsonify({'error': 'No user email in session'}), 400
    if not str(incident_id).isdigit():
        return jsonify({'error': 'Only Graph incidents (numeric ID) can be assigned'}), 400
    try:
        graph_patch_incident(incident_id, {'assignedTo': email})
        graph_post_comment(incident_id,
                           f'Assigned to {name} ({email}) via SOC Dashboard')
        update_incident_field(incident_id, 'assigned_to', email)
        print(f'📌 Incident {incident_id} assigned to {email}')
        return jsonify({'success': True, 'assignedTo': email})
    except Exception as exc:
        print(f'❌ Assign incident {incident_id} failed: {exc}')
        return jsonify({'error': 'Failed to assign incident'}), 502


@app.route('/api/incidents/<incident_id>/escalate', methods=['POST'])
@require_login
def escalate_incident(incident_id):
    """Escalate: bump severity, tag, comment, email notification."""
    user = session.get('user', {})
    email = user.get('email', '')
    name = user.get('name', email)
    if not str(incident_id).isdigit():
        return jsonify({'error': 'Only Graph incidents (numeric ID) can be escalated'}), 400

    body = request.get_json(silent=True) or {}
    severity = body.get('severity', 'high')
    if severity not in ('high', 'critical'):
        return jsonify({'error': 'Severity must be high or critical'}), 400
    category = body.get('category', '')
    notes = body.get('notes', '')
    reason = f'{category}. {notes}'.strip(' .') if category else (notes or 'No reason provided')
    # Graph API max severity is 'high' — map 'critical' for the API call
    graph_severity = 'high' if severity == 'critical' else severity

    try:
        # 1. Bump severity + tag
        graph_patch_incident(incident_id, {
            'severity': graph_severity,
            'customTags': ['Escalated'],
        })
        # 2. Comment
        graph_post_comment(incident_id,
            f'ESCALATED by {name} ({email}) via SOC Dashboard.\n'
            f'Severity: {severity.title()}\n'
            f'Category: {category or "N/A"}\n'
            f'Notes: {notes or "N/A"}')
        # 3. Update local DB
        update_incident_field(incident_id, 'severity', severity.title())

        # ── Notification dispatch ────────────────────────────────────────
        methods_csv = get_config('ESCALATION_METHODS') or 'email'
        enabled = {m.strip().lower() for m in methods_csv.split(',') if m.strip()}
        user_token = get_user_token() if ('email' in enabled or 'teams_graph' in enabled) else None

        # 4a. Email notification (delegated — from user's own mailbox)
        if 'email' in enabled:
            escalation_email = get_config('ESCALATION_EMAIL') or ''
            recipients = [r.strip() for r in escalation_email.split(',') if r.strip()]
            if recipients:
                if user_token:
                    subject = f'[SOC] Incident {incident_id} Escalated — {severity.title()}'
                    html_body = (
                        f'<h2>Incident {incident_id} Escalated</h2>'
                        f'<p><b>Severity:</b> {severity.title()}</p>'
                        f'<p><b>Escalated by:</b> {name} ({email})</p>'
                        f'<p><b>Category:</b> {category or "N/A"}</p>'
                        f'<p><b>Notes:</b> {notes or "N/A"}</p>'
                        f'<p><a href="https://security.microsoft.com/incidents/{incident_id}">'
                        f'Open in Defender Portal</a></p>'
                    )
                    try:
                        graph_send_mail(user_token, subject, html_body, recipients)
                        print(f'📧 Escalation email sent to {recipients}')
                    except Exception as mail_exc:
                        print(f'⚠️  Escalation email failed: {mail_exc}')
                else:
                    print('⚠️  No delegated token — email notification skipped')

        # 4b. Teams Graph API notification (delegated — posts as user)
        if 'teams_graph' in enabled:
            teams_channel = get_config('TEAMS_CHANNEL_ID') or ''
            if teams_channel.strip():
                if user_token:
                    try:
                        send_teams_channel_escalation(
                            teams_channel.strip(), incident_id,
                            severity.title(), f'{name} ({email})',
                            category, notes,
                            access_token=user_token,
                        )
                        print(f'💬 Teams Graph API notification sent')
                    except Exception as tg_exc:
                        print(f'⚠️  Teams Graph API notification failed: {tg_exc}')
                else:
                    print('⚠️  No delegated token — Teams Graph notification skipped')

        # 4c. Teams Webhook notification (no auth needed — URL contains token)
        if 'teams_webhook' in enabled:
            webhook_url = get_config('TEAMS_WEBHOOK_URL') or ''
            if webhook_url.strip():
                try:
                    send_teams_webhook_escalation(
                        webhook_url.strip(), incident_id,
                        severity.title(), f'{name} ({email})',
                        category, notes,
                    )
                    print(f'💬 Teams Webhook notification sent')
                except Exception as tw_exc:
                    print(f'⚠️  Teams Webhook notification failed: {tw_exc}')

        print(f'⚠️  Incident {incident_id} escalated by {email}')
        return jsonify({'success': True, 'severity': severity.title()})
    except Exception as exc:
        print(f'❌ Escalate incident {incident_id} failed: {exc}')
        return jsonify({'error': 'Failed to escalate incident'}), 502


@app.route('/api/incidents/<incident_id>/close', methods=['POST'])
@require_login
def close_incident(incident_id):
    """Close a Graph Security incident with Graph-supported status fields."""
    if not _feature_enabled('CLOSE_INCIDENT_ENABLED'):
        return jsonify({'error': 'Close Incident is disabled — enable it in Settings'}), 403
    if not str(incident_id).isdigit():
        return jsonify({'error': 'Only Graph incidents (numeric ID) can be closed'}), 400

    user = session.get('user', {})
    email = user.get('email', '')
    name = user.get('name', email)
    body = request.get_json(silent=True) or {}

    allowed_classifications = {
        'unknown',
        'falsePositive',
        'truePositive',
        'informationalExpectedActivity',
    }
    allowed_determinations = {
        'unknown',
        'apt',
        'malware',
        'securityPersonnel',
        'securityTesting',
        'unwantedSoftware',
        'other',
        'multiStagedAttack',
        'compromisedAccount',
        'phishing',
        'maliciousUserActivity',
        'notMalicious',
        'notEnoughData',
    }

    classification = body.get('classification', 'truePositive')
    determination = body.get('determination', 'multiStagedAttack')
    comment = (body.get('comment') or '').strip()

    if classification not in allowed_classifications:
        return jsonify({'error': 'Invalid classification'}), 400
    if determination not in allowed_determinations:
        return jsonify({'error': 'Invalid determination'}), 400

    try:
        graph_patch_incident(incident_id, {
            'status': 'resolved',
            'classification': classification,
            'determination': determination,
            'customTags': ['ClosedBySOCDashboard'],
        })
        graph_post_comment(
            incident_id,
            f'CLOSED by {name} ({email}) via SOC Dashboard.\n'
            f'Classification: {classification}\n'
            f'Determination: {determination}\n'
            f'Comment: {comment or "N/A"}'
        )

        update_incident_field(incident_id, 'status', 'Closed')
        update_incident_field(incident_id, 'classification', classification)
        update_incident_field(incident_id, 'determination', determination)

        print(f'✅ Incident {incident_id} closed by {email}')
        return jsonify({
            'success': True,
            'status': 'Closed',
            'classification': classification,
            'determination': determination,
        })
    except Exception as exc:
        print(f'❌ Close incident {incident_id} failed: {exc}')
        return jsonify({'error': 'Failed to close incident'}), 502


# ─── Cases CRUD API ──────────────────────────────────────────────────────────

@app.route('/api/cases', methods=['GET'])
@require_login
def list_cases():
    try:
        status = request.args.get('status')
        return jsonify(get_cases(status))
    except Exception as e:
        print(f'❌ Failed to list cases: {e}')
        return jsonify({'error': 'Failed to load cases'}), 500


@app.route('/api/cases', methods=['POST'])
@require_login
def create_case_route():
    user = session.get('user', {})
    body = request.get_json(silent=True) or {}
    title = (body.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'Title is required'}), 400
    priority = body.get('priority', 'Medium')
    if priority not in ('Very low', 'Low', 'Medium', 'High', 'Critical'):
        return jsonify({'error': 'Invalid priority'}), 400
    try:
        case_id = create_case(
            title=title,
            priority=priority,
            description=(body.get('description') or '').strip(),
            assigned_to=(body.get('assigned_to') or '').strip(),
            created_by=user.get('email', ''),
            incident_ids=body.get('incident_ids'),
        )
        print(f'📁 Case #{case_id} created by {user.get("email", "?")}')
        return jsonify({'success': True, 'case_id': case_id}), 201
    except Exception as e:
        print(f'❌ Failed to create case: {e}')
        return jsonify({'error': 'Failed to create case'}), 500


@app.route('/api/cases/<int:case_id>', methods=['GET'])
@require_login
def get_case_route(case_id):
    case = get_case(case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    return jsonify(case)


@app.route('/api/cases/<int:case_id>', methods=['PATCH'])
@require_login
def update_case_route(case_id):
    body = request.get_json(silent=True) or {}
    updates = {}
    for field in ('title', 'status', 'priority', 'assigned_to', 'description'):
        if field in body:
            updates[field] = body[field]
    incident_ids = body.get('incident_ids')  # None = don't touch, list = replace
    try:
        if not update_case(case_id, updates, incident_ids):
            return jsonify({'error': 'Case not found or no changes'}), 404
        return jsonify({'success': True})
    except Exception as e:
        print(f'❌ Failed to update case {case_id}: {e}')
        return jsonify({'error': 'Failed to update case'}), 500


@app.route('/api/cases/<int:case_id>', methods=['DELETE'])
@require_login
def delete_case_route(case_id):
    if not delete_case(case_id):
        return jsonify({'error': 'Case not found'}), 404
    print(f'🗑️  Case #{case_id} deleted by {session.get("user", {}).get("email", "?")}')
    return jsonify({'success': True})


# ── Feature toggles API ─────────────────────────

def _feature_enabled(key: str) -> bool:
    """Check if a feature toggle is enabled (truthy string)."""
    val = (get_config(key) or '').strip().lower()
    return val in ('true', '1', 'yes', 'on')


@app.route('/api/features')
@require_login
def get_features():
    """Return current feature toggle states."""
    try:
        incidents_display_limit = int(get_config('INCIDENTS_DISPLAY_LIMIT', '100') or '100')
    except (TypeError, ValueError):
        incidents_display_limit = 100
    incidents_display_limit = max(10, min(1000, incidents_display_limit))
    mdti_raw = (get_config('MDTI_ENABLED', 'false') or 'false').strip().lower()
    mdti_enabled = mdti_raw in ('true', '1', 'yes', 'on')
    return jsonify({
        'ai_assistant': _feature_enabled('AI_ASSISTANT_ENABLED'),
        'kql_console': _feature_enabled('KQL_CONSOLE_ENABLED'),
        'mdti_enabled': mdti_enabled,
        'ai_auto_enrich': _feature_enabled('AI_AUTO_ENRICH_ENABLED'),
        'ai_auto_comment': _feature_enabled('AI_AUTO_COMMENT_ENABLED'),
        'close_incident': _feature_enabled('CLOSE_INCIDENT_ENABLED'),
        'logs_enabled': _feature_enabled('LOGS_ENABLED'),
        'ioc_upload': _feature_enabled('IOC_UPLOAD_ENABLED'),
        'security_copilot': _feature_enabled('SECURITY_COPILOT_ENABLED'),
        'copilot_auto_enrich': _feature_enabled('COPILOT_AUTO_ENRICH_ENABLED'),
        'autonomous_triage': _feature_enabled('TRIAGE_ENABLED'),
        'response_actions': _feature_enabled('RESPONSE_ACTIONS_ENABLED'),
        'response_dry_run': (get_config('RESPONSE_DRY_RUN', 'true') or 'true').strip().lower()
                            in ('true', '1', 'yes', 'on'),
        'incidents_display_limit': incidents_display_limit,
    })


# ── Sentinel Workspaces API ─────────────────────

@app.route('/api/workspaces', methods=['GET'])
@require_login
def list_workspaces():
    """Return all registered Sentinel workspaces."""
    return jsonify(get_workspaces())

@app.route('/api/workspaces', methods=['POST'])
@require_admin
def create_workspace():
    """Register a new Sentinel workspace."""
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({'error': 'Missing JSON payload'}), 400
    ws_id = (payload.get('workspace_id') or '').strip()
    name = (payload.get('name') or '').strip()
    if not ws_id or not name:
        return jsonify({'error': 'workspace_id and name are required'}), 400
    try:
        row_id = add_workspace(ws_id, name, is_default=payload.get('is_default', False))
    except Exception:
        return jsonify({'error': 'Workspace ID already exists'}), 409
    return jsonify({'id': row_id, 'workspace_id': ws_id, 'name': name}), 201

@app.route('/api/workspaces/<int:row_id>', methods=['DELETE'])
@require_admin
def delete_workspace(row_id):
    """Remove a registered workspace."""
    if remove_workspace(row_id):
        return jsonify({'deleted': True})
    return jsonify({'error': 'Workspace not found'}), 404

@app.route('/api/workspaces/<int:row_id>/default', methods=['PUT'])
@require_admin
def set_workspace_default(row_id):
    """Set a workspace as the default."""
    if set_default_workspace(row_id):
        return jsonify({'is_default': True})
    return jsonify({'error': 'Workspace not found'}), 404


# ── KQL Console API ─────────────────────────────

@app.route('/api/sentinel/query', methods=['POST'])
@require_login
def sentinel_query():
    """Execute a KQL query against Log Analytics."""
    if not _feature_enabled('KQL_CONSOLE_ENABLED'):
        return jsonify({'error': 'KQL Console is disabled — enable it in Settings'}), 403
    payload = request.get_json(silent=True)
    if not payload or not payload.get('query'):
        return jsonify({'error': 'Missing query'}), 400
    try:
        from sentinel_kql import run_kql
        ws = payload.get('workspace_id') or None
        rows = run_kql(payload['query'], workspace_id=ws)
        return jsonify({'columns': list(rows[0].keys()) if rows else [], 'rows': rows})
    except (ValueError, RuntimeError) as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception:
        return jsonify({'error': 'KQL query failed — check server logs'}), 500


# ── AI Assistant API ─────────────────────────────

@app.route('/api/sentinel/ai', methods=['POST'])
@require_login
def sentinel_ai():
    """Ask the AI assistant a security question."""
    if not _feature_enabled('AI_ASSISTANT_ENABLED'):
        return jsonify({'error': 'AI Assistant is disabled — enable it in Settings'}), 403
    payload = request.get_json(silent=True)
    if not payload or not payload.get('question'):
        return jsonify({'error': 'Missing question'}), 400
    try:
        from ai_assistant import ask_agent
        user_token = get_user_sentinel_token()
        triage_token = get_user_triage_token()
        result = ask_agent(
            payload['question'],
            payload.get('history'),
            user_token=user_token,
            triage_token=triage_token,
        )
        return jsonify(result)
    except Exception:
        return jsonify({'error': 'AI request failed — check server logs'}), 500


# ── Attack Story API ─────────────────────────────

@app.route('/api/incidents/<incident_id>/attack-story', methods=['POST'])
@require_login
def incident_attack_story(incident_id):
    """Generate or retrieve a cached AI attack story for an incident."""
    if not _feature_enabled('AI_ASSISTANT_ENABLED'):
        return jsonify({'error': 'AI Assistant is disabled'}), 403

    # Check cache first
    cached = get_attack_story(incident_id)
    if cached:
        return jsonify({'story': cached['story'], 'model': cached.get('model', ''), 'cached': True})

    try:
        from ai_assistant import ask_agent
        user_token = get_user_sentinel_token()
        triage_token = get_user_triage_token()
        question = f'Investigate incident {incident_id}. Provide a full attack story: timeline, entities, MITRE tactics, and recommended next steps.'
        result = ask_agent(question, user_token=user_token, triage_token=triage_token)
        story = result.get('answer', '')
        if story:
            model = get_config('FOUNDRY_DEPLOYMENT') or ''
            save_attack_story(incident_id, story, model)
        return jsonify({'story': story, 'model': get_config('FOUNDRY_DEPLOYMENT') or '', 'cached': False})
    except Exception:
        return jsonify({'error': 'Failed to generate attack story — check server logs'}), 500


@app.route('/api/incidents/<incident_id>/ai-enrich', methods=['POST'])
@require_login
def incident_ai_enrich(incident_id):
    """AI-analyse an incident and post the analysis as a Sentinel comment."""
    if not _feature_enabled('AI_ASSISTANT_ENABLED'):
        return jsonify({'error': 'AI Assistant is disabled'}), 403

    body = request.get_json(silent=True) or {}
    title = body.get('title', f'Incident {incident_id}')
    severity = body.get('severity', 'unknown')
    entities = body.get('entities') or []
    mitre = body.get('mitreTechniques') or []

    # Build a context-rich prompt so the AI skips discovery
    entity_lines = '\n'.join(f'  - {e.get("type","?")}: {e.get("name","?")} (verdict: {e.get("verdict","unknown")})' for e in entities[:30])
    prompt = (
        f'Analyse Microsoft Sentinel incident {incident_id}.\n'
        f'Title: {title}\nSeverity: {severity}\n'
        + (f'Entities:\n{entity_lines}\n' if entity_lines else '')
        + (f'MITRE Techniques: {", ".join(mitre)}\n' if mitre else '')
        + '\nProvide:\n1. Brief summary of what happened\n'
        '2. Risk assessment (Critical/High/Medium/Low) with justification\n'
        '3. Affected assets and accounts\n'
        '4. MITRE ATT&CK mapping if applicable\n'
        '5. Recommended response actions\n'
        'Be concise — max 1500 characters.'
    )

    try:
        from ai_assistant import ask_agent
        user_token = get_user_sentinel_token()
        triage_token = get_user_triage_token()
        result = ask_agent(prompt, user_token=user_token, triage_token=triage_token)
        analysis = result.get('answer', '')
        if not analysis:
            return jsonify({'error': 'AI returned an empty analysis'}), 502

        # Post as comment to Sentinel via Graph API (with dedup guard)
        comment_posted = False
        if str(incident_id).isdigit() and _feature_enabled('AI_AUTO_COMMENT_ENABLED'):
            cache_key = f'ai_comment_{incident_id}'
            already_posted = getattr(app, '_comment_cache', {}).get(cache_key, 0)
            import time as _time
            if _time.time() - already_posted > 120:  # 2-minute dedup window
                try:
                    comment_text = f'[SOC Dashboard — AI Analysis]\n\n{analysis[:960]}'
                    graph_post_comment(incident_id, comment_text[:1000])
                    comment_posted = True
                    if not hasattr(app, '_comment_cache'):
                        app._comment_cache = {}
                    app._comment_cache[cache_key] = _time.time()
                except Exception as exc:
                    app.logger.warning('⚠️  AI comment post failed for %s: %s', incident_id, exc)
            else:
                app.logger.info('⏭️  Skipped duplicate AI comment for %s', incident_id)
                comment_posted = True  # already posted recently

        return jsonify({'analysis': analysis, 'comment_posted': comment_posted})
    except Exception:
        return jsonify({'error': 'AI enrichment failed — check server logs'}), 500


# ── Security Copilot Enrichment API ─────────────

def _get_enrichment_previews(incident_ids: list) -> dict:
    """Build a lightweight enrichment preview map for dashboard-data."""
    try:
        batch = get_enrichments_batch([str(i) for i in incident_ids])
        return {
            iid: {
                'risk_score': e.get('risk_score'),
                'source': e.get('source'),
                'created_at': e.get('created_at'),
            }
            for iid, e in batch.items()
        }
    except Exception:
        return {}


@app.route('/api/incidents/<incident_id>/copilot-enrich', methods=['POST'])
@require_login
def copilot_enrich_incident(incident_id):
    """On-demand Security Copilot enrichment via Foundry agent."""
    if not _feature_enabled('SECURITY_COPILOT_ENABLED'):
        return jsonify({'error': 'Security Copilot integration is disabled'}), 403
    try:
        from security_copilot import enrich_via_foundry
        result = enrich_via_foundry(incident_id)
        app.logger.info('Copilot enrich %s: success=%s cached=%s', incident_id,
                        result.get('success'), result.get('cached'))
        if result.get('success'):
            # Post enrichment summary as Sentinel comment (skip for cached)
            comment_posted = False
            if not result.get('cached') and str(incident_id).isdigit():
                try:
                    lines = ['[SOC Dashboard — Security Copilot Enrichment]']
                    if result.get('risk_score') is not None:
                        lines.append(f'Risk Score: {result["risk_score"]}/100')
                    if result.get('summary'):
                        lines.append(f'\n{result["summary"][:700]}')
                    if result.get('recommended_actions'):
                        lines.append('\nRecommended Actions:')
                        for i, a in enumerate(result['recommended_actions'][:5], 1):
                            lines.append(f'{i}. {a[:80]}')
                    graph_post_comment(incident_id, '\n'.join(lines)[:1000])
                    comment_posted = True
                    app.logger.info('✅ Copilot comment posted for incident %s', incident_id)
                except Exception as exc:
                    app.logger.warning('⚠️  Copilot comment post failed for %s: %s', incident_id, exc)
            else:
                app.logger.info('Copilot skip comment: cached=%s isdigit=%s',
                                result.get('cached'), str(incident_id).isdigit())
            result['comment_posted'] = comment_posted
            return jsonify(result)
        return jsonify({'error': result.get('error', 'Enrichment failed')}), 502
    except Exception as exc:
        app.logger.exception('Copilot enrich exception for %s', incident_id)
        return jsonify({'error': 'Enrichment request failed — check server logs'}), 500


@app.route('/api/incidents/<incident_id>/enrichment')
@require_login
def get_incident_enrichment(incident_id):
    """Return the latest enrichment data for an incident."""
    enrichment = get_enrichment(incident_id)
    if not enrichment:
        return jsonify({'enrichment': None})
    return jsonify({'enrichment': enrichment})


@app.route('/api/incidents/bulk-enrich', methods=['POST'])
@require_login
def bulk_enrich_incidents():
    """Enrich multiple incidents at once (manual trigger)."""
    if not _feature_enabled('SECURITY_COPILOT_ENABLED'):
        return jsonify({'error': 'Security Copilot integration is disabled'}), 403
    body = request.get_json(silent=True) or {}
    ids = body.get('incident_ids', [])
    if not ids or not isinstance(ids, list):
        return jsonify({'error': 'Missing incident_ids array'}), 400
    ids = [str(i) for i in ids[:20]]  # cap at 20
    try:
        from security_copilot import auto_enrich_new_incidents
        result = auto_enrich_new_incidents(ids)
        return jsonify(result)
    except Exception:
        return jsonify({'error': 'Bulk enrichment failed — check server logs'}), 500


@app.route('/api/webhooks/copilot-enrichment', methods=['POST'])
def copilot_webhook():
    """Receive enrichment callbacks from Logic App.
    Validates shared secret via X-Webhook-Secret header."""
    expected_secret = get_config('COPILOT_WEBHOOK_SECRET')
    if not expected_secret:
        return jsonify({'error': 'Webhook not configured'}), 503
    provided_secret = request.headers.get('X-Webhook-Secret', '')
    if not secrets.compare_digest(provided_secret, expected_secret):
        return jsonify({'error': 'Unauthorized'}), 401
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({'error': 'Missing JSON payload'}), 400
    try:
        from security_copilot import process_webhook_payload
        result = process_webhook_payload(payload)
        if result.get('success'):
            return jsonify({'success': True})
        return jsonify({'error': result.get('error', 'Processing failed')}), 400
    except Exception:
        return jsonify({'error': 'Webhook processing failed'}), 500


@app.route('/api/enrichment-stats')
@require_login
def enrichment_stats():
    """Return enrichment coverage statistics."""
    try:
        stats = get_enrichment_stats()
        return jsonify(stats)
    except Exception:
        return jsonify({'error': 'Failed to get enrichment stats'}), 500


# ── IOC Upload API (admin-only) ─────────────────

@app.route('/api/ioc/upload', methods=['POST'])
@require_admin
def ioc_upload_single():
    """Upload a single IOC to Sentinel."""
    if not _feature_enabled('IOC_UPLOAD_ENABLED'):
        return jsonify({'error': 'IOC upload is disabled — enable it in Settings'}), 403
    body = request.get_json(silent=True)
    if not body:
        return jsonify({'error': 'Missing JSON payload'}), 400
    ioc_type = body.get('type', '').strip()
    value = body.get('value', '').strip()
    if not ioc_type or not value:
        return jsonify({'error': 'Missing type or value'}), 400
    try:
        from ioc_upload import upload_single_ioc
        result = upload_single_ioc(
            ioc_type=ioc_type,
            value=value,
            confidence=int(body.get('confidence', 50)),
            description=body.get('description', ''),
            tags=body.get('tags') if isinstance(body.get('tags'), list) else [],
            valid_until=body.get('validUntil'),
        )
        print(f'🛡️  IOC uploaded: {ioc_type}={value} by {session.get("user", {}).get("email", "?")}')
        return jsonify({'success': True, 'indicator': result})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except RuntimeError:
        return jsonify({'error': 'Failed to upload IOC to Sentinel'}), 502


@app.route('/api/ioc/upload-csv', methods=['POST'])
@require_admin
def ioc_upload_csv():
    """Upload IOCs from a CSV file."""
    if not _feature_enabled('IOC_UPLOAD_ENABLED'):
        return jsonify({'error': 'IOC upload is disabled — enable it in Settings'}), 403
    f = request.files.get('file')
    if not f:
        return jsonify({'error': 'No file uploaded'}), 400
    if not f.filename.lower().endswith('.csv'):
        return jsonify({'error': 'Only .csv files are accepted'}), 400
    content = f.read().decode('utf-8', errors='replace')
    # Limit size: 10 MB
    if len(content) > 10 * 1024 * 1024:
        return jsonify({'error': 'CSV file too large (max 10 MB)'}), 400
    try:
        from ioc_upload import parse_csv, upload_bulk_iocs
        iocs = parse_csv(content)
        if not iocs:
            return jsonify({'error': 'No valid IOCs found in CSV'}), 400
        result = upload_bulk_iocs(iocs, source='CSV Upload')
        user = session.get('user', {}).get('email', '?')
        print(f'🛡️  CSV upload: {result["uploaded"]} OK, {result["failed"]} failed — by {user}')
        return jsonify({'success': True, **result})
    except Exception:
        return jsonify({'error': 'Failed to process CSV upload'}), 500


@app.route('/api/ioc/stream-import', methods=['POST'])
@require_admin
def ioc_stream_import():
    """One-time import from a URL feed."""
    if not _feature_enabled('IOC_UPLOAD_ENABLED'):
        return jsonify({'error': 'IOC upload is disabled — enable it in Settings'}), 403
    body = request.get_json(silent=True)
    if not body or not body.get('url'):
        return jsonify({'error': 'Missing feed URL'}), 400
    try:
        from ioc_upload import fetch_feed, upload_bulk_iocs
        feed_format = body.get('format', 'plaintext')
        ioc_type = body.get('iocType', 'ipv4-addr')
        iocs = fetch_feed(body['url'], feed_format, ioc_type)
        if not iocs:
            return jsonify({'error': 'No IOCs found in feed'}), 400
        result = upload_bulk_iocs(iocs, source=f'Stream: {body["url"][:80]}')
        user = session.get('user', {}).get('email', '?')
        print(f'🛡️  Stream import: {result["uploaded"]} OK from {body["url"][:60]} — by {user}')
        return jsonify({'success': True, **result})
    except Exception:
        return jsonify({'error': 'Failed to import feed'}), 502


@app.route('/api/ioc/feeds', methods=['GET'])
@require_admin
def ioc_list_feeds():
    """List all configured IOC feeds."""
    if not _feature_enabled('IOC_UPLOAD_ENABLED'):
        return jsonify({'error': 'IOC upload is disabled'}), 403
    from database import get_feeds
    return jsonify(get_feeds())


@app.route('/api/ioc/feeds', methods=['POST'])
@require_admin
def ioc_add_feed():
    """Add a new IOC feed."""
    if not _feature_enabled('IOC_UPLOAD_ENABLED'):
        return jsonify({'error': 'IOC upload is disabled'}), 403
    body = request.get_json(silent=True)
    if not body or not body.get('name') or not body.get('url'):
        return jsonify({'error': 'Missing name or url'}), 400
    from database import save_feed
    feed_id = save_feed(
        name=body['name'],
        url=body['url'],
        fmt=body.get('format', 'plaintext'),
        poll_interval_hours=int(body.get('pollIntervalHours', 24)),
        ioc_type_default=body.get('iocTypeDefault', 'ipv4-addr'),
    )
    print(f'🛡️  Feed added: {body["name"]} (#{feed_id})')
    return jsonify({'success': True, 'id': feed_id}), 201


@app.route('/api/ioc/feeds/<int:feed_id>', methods=['DELETE'])
@require_admin
def ioc_delete_feed(feed_id):
    """Remove an IOC feed."""
    if not _feature_enabled('IOC_UPLOAD_ENABLED'):
        return jsonify({'error': 'IOC upload is disabled'}), 403
    from database import delete_feed
    if delete_feed(feed_id):
        print(f'🗑️  Feed #{feed_id} deleted')
        return jsonify({'success': True})
    return jsonify({'error': 'Feed not found'}), 404


@app.route('/api/ioc/feeds/<int:feed_id>', methods=['PUT'])
@require_admin
def ioc_update_feed(feed_id):
    """Update an IOC feed."""
    if not _feature_enabled('IOC_UPLOAD_ENABLED'):
        return jsonify({'error': 'IOC upload is disabled'}), 403
    body = request.get_json(silent=True)
    if not body:
        return jsonify({'error': 'Missing JSON payload'}), 400
    from database import update_feed
    update_feed(feed_id, body)
    return jsonify({'success': True})


@app.route('/api/ioc/feeds/<int:feed_id>/poll', methods=['POST'])
@require_admin
def ioc_poll_feed(feed_id):
    """Trigger an immediate poll for a specific feed."""
    if not _feature_enabled('IOC_UPLOAD_ENABLED'):
        return jsonify({'error': 'IOC upload is disabled'}), 403
    from database import get_feed
    feed = get_feed(feed_id)
    if not feed:
        return jsonify({'error': 'Feed not found'}), 404
    try:
        from ioc_upload import poll_feed
        result = poll_feed(
            feed_id=feed_id,
            url=feed['url'],
            feed_format=feed['format'],
            ioc_type_default=feed['ioc_type_default'],
            source=f'Feed: {feed["name"]}',
        )
        return jsonify({'success': True, **result})
    except Exception:
        return jsonify({'error': 'Feed poll failed'}), 502


@app.route('/api/ioc/presets')
@require_admin
def ioc_feed_presets():
    """Return built-in feed preset configurations."""
    if not _feature_enabled('IOC_UPLOAD_ENABLED'):
        return jsonify({'error': 'IOC upload is disabled'}), 403
    from ioc_upload import FEED_PRESETS
    return jsonify(FEED_PRESETS)


# ── Logs API ─────────────────────────────────────

_LOG_FILES = {
    'error':  lambda: os.getenv('LOG_PATH', '/var/log/soc-dashboard/error.log'),
    'access': lambda: os.getenv('ACCESS_LOG_PATH', '/var/log/soc-dashboard/access.log'),
    'service': None,  # special: journalctl
}

import re as _re
import subprocess as _subprocess

_GUNICORN_RE = _re.compile(
    r'^\[(?P<ts>[^\]]+)\]\s+\[\d+\]\s+\[(?P<level>\w+)\]\s+(?P<msg>.*)$'
)
_ACCESS_RE = _re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\S+)\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
)
_PYTHON_LOG_RE = _re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})[,.]?\d*\s+(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+(?P<msg>.*)$',
    _re.IGNORECASE
)
_SYSTEMD_RE = _re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+\S+\[\d+\]:\s*(?P<msg>.*)$'
)

_EMOJI_LEVEL = {
    '✅': 'INFO', '⚙': 'INFO', '📊': 'INFO', '💾': 'INFO',
    '🌐': 'INFO', '☑': 'INFO', '📦': 'INFO',
    '⚠': 'WARNING', '❌': 'ERROR', '🚨': 'ERROR',
}


def _infer_emoji_level(msg: str) -> str:
    """Infer log level from leading emoji character."""
    stripped = msg.lstrip()
    for ch, level in _EMOJI_LEVEL.items():
        if stripped.startswith(ch):
            return level
    return ''


def _parse_log_line(line: str, log_type: str) -> dict:
    """Parse a raw log line into structured fields."""
    raw = line.rstrip('\n')
    if log_type == 'access':
        m = _ACCESS_RE.match(raw)
        if m:
            status = int(m.group('status'))
            level = 'ERROR' if status >= 500 else 'WARNING' if status >= 400 else 'INFO'
            return {'ts': m.group('ts'), 'level': level, 'msg': f"{m.group('method')} {m.group('path')} → {status}",
                    'ip': m.group('ip'), 'status': status, 'ua': m.group('ua'), 'raw': raw}
    elif log_type == 'service':
        m = _SYSTEMD_RE.match(raw)
        if m:
            msg = m.group('msg')
            level = _infer_emoji_level(msg) or 'INFO'
            return {'ts': m.group('ts'), 'level': level, 'msg': msg, 'raw': raw}
    else:
        m = _GUNICORN_RE.match(raw)
        if m:
            return {'ts': m.group('ts'), 'level': m.group('level').upper(), 'msg': m.group('msg'), 'raw': raw}
        m = _PYTHON_LOG_RE.match(raw)
        if m:
            return {'ts': m.group('ts'), 'level': m.group('level').upper(), 'msg': m.group('msg'), 'raw': raw}
        # Try emoji level inference for captured print() output
        level = _infer_emoji_level(raw)
        if level:
            return {'ts': '', 'level': level, 'msg': raw, 'raw': raw}
    # Fallback — unparsed line
    return {'ts': '', 'level': '', 'msg': raw, 'raw': raw}


@app.route('/api/logs')
@require_admin
def get_logs():
    """Return recent application log lines (admin-only, feature-gated)."""
    if not _feature_enabled('LOGS_ENABLED'):
        return jsonify({'error': 'Logs viewer is disabled — enable it in Settings'}), 403

    log_type = request.args.get('file', 'error')
    if log_type not in _LOG_FILES:
        return jsonify({'error': 'Invalid log file'}), 400
    lines_requested = min(int(request.args.get('lines', 200)), 2000)

    try:
        # Service log: read from journalctl
        if log_type == 'service':
            unit = 'dashboard.service'
            proc = _subprocess.run(
                ['journalctl', '-u', unit, '--no-pager', '-n', str(lines_requested)],
                capture_output=True, text=True, timeout=10,
            )
            raw_lines = proc.stdout.splitlines(keepends=True) if proc.stdout else []
            parsed = [_parse_log_line(l, log_type) for l in raw_lines]
            return jsonify({'lines': raw_lines, 'parsed': parsed, 'path': f'journalctl -u {unit}', 'type': log_type})

        log_path = _LOG_FILES[log_type]()
        if not os.path.isfile(log_path):
            return jsonify({'lines': [], 'parsed': [], 'path': log_path, 'error': 'Log file not found'})
        from collections import deque
        with open(log_path, 'r', errors='replace') as f:
            tail = deque(f, maxlen=lines_requested)
        raw_lines = list(tail)
        parsed = [_parse_log_line(l, log_type) for l in raw_lines]
        return jsonify({'lines': raw_lines, 'parsed': parsed, 'path': log_path, 'type': log_type})
    except Exception:
        return jsonify({'error': 'Failed to read log file'}), 500


@app.route('/api/logs/download')
@require_admin
def download_logs():
    """Download the current log file as a text attachment."""
    if not _feature_enabled('LOGS_ENABLED'):
        return jsonify({'error': 'Logs viewer is disabled'}), 403

    log_type = request.args.get('file', 'error')
    if log_type not in _LOG_FILES:
        return jsonify({'error': 'Invalid log file'}), 400

    try:
        if log_type == 'service':
            proc = _subprocess.run(
                ['journalctl', '-u', 'dashboard.service', '--no-pager', '-n', '2000'],
                capture_output=True, text=True, timeout=10,
            )
            from io import BytesIO
            buf = BytesIO((proc.stdout or '').encode('utf-8'))
            return send_file(buf, mimetype='text/plain', as_attachment=True,
                             download_name=f'dashboard-service-{datetime.utcnow().strftime("%Y%m%d-%H%M%S")}.log')

        log_path = _LOG_FILES[log_type]()
        if not os.path.isfile(log_path):
            return jsonify({'error': 'Log file not found'}), 404
        return send_file(log_path, mimetype='text/plain', as_attachment=True,
                         download_name=f'{log_type}-{datetime.utcnow().strftime("%Y%m%d-%H%M%S")}.log')
    except Exception:
        return jsonify({'error': 'Failed to download log file'}), 500


@app.route('/')
@require_login
def serve_dashboard():
    """Serve the dashboard HTML"""
    return send_file('soc-dashboard-live.html')

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Starting SOC Dashboard Backend Server")
    print("="*60)
    
    if DB_AVAILABLE:
        print("✅ Database mode: SQLite with timeline filtering")
        try:
            stats = get_database_stats()
            print(f"📊 Database contains:")
            print(f"   • {stats['incidents']} incidents")
            print(f"   • {stats['alerts']} alerts")
            print(f"   • {stats['entities']} entities")
            print(f"   • Date range: {stats['oldest_incident']} to {stats['newest_incident']}")
        except:
            print("⚠️  Database exists but may be empty. Run: python migrate_json_to_db.py")
    else:
        print("⚠️  JSON fallback mode (database not available)")
    
    print("\n💡 API Endpoints:")
    print("   • GET /api/dashboard-data (supports filtering)")
    print("   • GET /api/dashboard-data?days=7 (last 7 days)")
    print("   • GET /api/dashboard-data?days=30 (last 30 days)")
    print("   • GET /api/dashboard-data?severity=High")
    print("   • GET /api/database-stats")
    print("\n🌐 Dashboard: http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(
        host=os.getenv('FLASK_HOST', '127.0.0.1'),
        port=int(os.getenv('FLASK_PORT', '5000')),
        debug=os.getenv('FLASK_DEBUG', '0') == '1'
    )
