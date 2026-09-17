"""
Flask blueprint for autonomous triage and gated response actions.

Registered from dashboard_backend.py with one line:

    from routes_triage import triage_bp
    app.register_blueprint(triage_bp)

Route conventions follow the existing app: @require_login for analyst routes,
@require_admin for anything that can change a production asset, and no
str(exc) in any JSON response.
"""

from __future__ import annotations

import logging

from flask import Blueprint, Response, jsonify, request, session

from auth import require_admin, require_login
from config_manager import get_config

import triage_db
from triage_agent import format_rca_markdown, triage_incident
from response_actions import describe_gates, execute_response_action, reject_action

log = logging.getLogger(__name__)

triage_bp = Blueprint('triage', __name__)

_TRUTHY = ('true', '1', 'yes', 'on')


def _flag(key: str, default: bool = False) -> bool:
    raw = get_config(key)
    if raw is None or raw == '':
        return default
    return str(raw).strip().lower() in _TRUTHY


def _actor() -> str:
    user = session.get('user', {}) or {}
    email = user.get('email', '')
    name = user.get('name', email)
    return f'{name} ({email})' if email else (name or 'unknown')


# ── Triage ───────────────────────────────────────────────────────────────────

@triage_bp.route('/api/incidents/<incident_id>/triage', methods=['POST'])
@require_login
def run_triage(incident_id):
    """Run an autonomous triage pass on one incident."""
    if not _flag('TRIAGE_ENABLED'):
        return jsonify({'error': 'Autonomous triage is disabled — enable it in Settings'}), 403

    body = request.get_json(silent=True) or {}
    force = bool(body.get('force'))

    if not force:
        existing = triage_db.get_triage(incident_id)
        if existing:
            return jsonify({'triage': existing, 'cached': True,
                            'actions': triage_db.get_response_actions(incident_id)})

    try:
        from auth import get_user_sentinel_token, get_user_triage_token
        result = triage_incident(
            incident_id,
            requested_by=_actor(),
            user_token=get_user_sentinel_token(),
            triage_token=get_user_triage_token(),
        )
    except Exception:
        log.exception('Triage route failed for %s', incident_id)
        return jsonify({'error': 'Triage failed — check server logs'}), 500

    if not result.get('success'):
        return jsonify({'error': result.get('error', 'Triage failed')}), 502

    # Auto-close is the only automatic execution path, and it self-gates.
    auto_results = []
    try:
        from response_actions import auto_execute_eligible
        auto_results = auto_execute_eligible(incident_id, result)
    except Exception:
        log.exception('Auto-close evaluation failed for %s', incident_id)

    return jsonify({
        'triage': triage_db.get_triage(incident_id),
        'cached': False,
        'actions': triage_db.get_response_actions(incident_id),
        'auto_executed': auto_results,
        'guard_notes': result.get('guard_notes', []),
        'comment_posted': result.get('comment_posted', False),
    })


@triage_bp.route('/api/incidents/<incident_id>/triage', methods=['GET'])
@require_login
def get_triage(incident_id):
    """Return the latest stored triage record for an incident."""
    triage = triage_db.get_triage(incident_id)
    if not triage:
        return jsonify({'triage': None, 'actions': []})
    return jsonify({'triage': triage,
                    'actions': triage_db.get_response_actions(incident_id)})


@triage_bp.route('/api/incidents/<incident_id>/triage/export', methods=['GET'])
@require_login
def export_triage(incident_id):
    """Download the triage record as a Markdown RCA document."""
    triage = triage_db.get_triage(incident_id)
    if not triage:
        return jsonify({'error': 'Incident has not been triaged'}), 404

    incident = triage_db.get_incident_by_id(incident_id) or {'id': incident_id}
    markdown = format_rca_markdown(incident, triage)
    filename = f'RCA-Incident-{incident_id}.md'
    return Response(
        markdown,
        mimetype='text/markdown',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@triage_bp.route('/api/triage-stats', methods=['GET'])
@require_login
def triage_stats():
    """Verdict distribution, evidence grades and action outcomes."""
    try:
        days = max(1, min(365, int(request.args.get('days', 30))))
    except (TypeError, ValueError):
        days = 30
    return jsonify(triage_db.get_triage_stats(days))


# ── Response actions ─────────────────────────────────────────────────────────

@triage_bp.route('/api/response/gates', methods=['GET'])
@require_login
def response_gates():
    """Which actions this deployment is currently permitted to perform."""
    return jsonify(describe_gates())


@triage_bp.route('/api/response/actions', methods=['GET'])
@require_login
def list_actions():
    """List response actions, newest first. Filter with ?status= and ?incident_id=."""
    status = request.args.get('status')
    if status and status not in triage_db.ACTION_STATUSES:
        return jsonify({'error': 'Invalid status filter'}), 400
    try:
        limit = max(1, min(500, int(request.args.get('limit', 100))))
    except (TypeError, ValueError):
        limit = 100
    return jsonify({'actions': triage_db.get_response_actions(
        incident_id=request.args.get('incident_id'), status=status, limit=limit)})


@triage_bp.route('/api/incidents/<incident_id>/actions', methods=['GET'])
@require_login
def incident_actions(incident_id):
    return jsonify({'actions': triage_db.get_response_actions(incident_id)})


@triage_bp.route('/api/response/actions/<int:action_id>/approve', methods=['POST'])
@require_admin
def approve_action(action_id):
    """
    Approve and execute a proposed containment action.

    Admin-only, and still subject to the RESPONSE_* gates and dry-run setting —
    approval alone cannot bypass a disabled action type.
    """
    body = request.get_json(silent=True) or {}
    note = (body.get('note') or '').strip()[:500]
    try:
        result = execute_response_action(action_id, _actor(), note)
    except Exception:
        log.exception('Approve route failed for action %s', action_id)
        return jsonify({'error': 'Action execution failed — check server logs'}), 500

    return jsonify(result), (200 if result.get('success') else 409)


@triage_bp.route('/api/response/actions/<int:action_id>/reject', methods=['POST'])
@require_login
def reject_action_route(action_id):
    """Decline a proposed action."""
    body = request.get_json(silent=True) or {}
    note = (body.get('note') or '').strip()[:500]
    try:
        result = reject_action(action_id, _actor(), note)
    except Exception:
        log.exception('Reject route failed for action %s', action_id)
        return jsonify({'error': 'Could not reject action — check server logs'}), 500
    return jsonify(result), (200 if result.get('success') else 409)
