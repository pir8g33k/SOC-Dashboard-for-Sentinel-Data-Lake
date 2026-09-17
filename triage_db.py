"""
Triage & Response persistence layer for SOC Dashboard.

Adds two tables on top of the existing schema:
  - incident_triage   — autonomous triage verdicts, RCA and investigation trace
  - response_actions  — proposed / approved / executed containment actions

Migration is idempotent: safe to call init_triage_schema() on every startup.
Follows repo conventions: parameterised SQL only, type hints, emoji log prefixes.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from database import get_connection

log = logging.getLogger(__name__)

# ── Canonical vocabularies ───────────────────────────────────────────────────

VERDICTS = ('TruePositive', 'FalsePositive', 'BenignPositive', 'Undetermined')
EVIDENCE_GRADES = ('verified', 'partial', 'unverified')

ACTION_STATUSES = (
    'proposed',    # agent suggested it; nothing has happened
    'rejected',    # analyst declined
    'executing',   # claimed by an executor
    'executed',    # API call succeeded
    'failed',      # API call attempted and failed
    'simulated',   # dry-run: validated and logged, deliberately NOT executed
)

# Action types the system will ever execute. Anything outside this set is dropped
# at parse time — the model cannot invent new capabilities for itself.
ACTION_TYPES = {
    'isolate_device':      'device',
    'revoke_sessions':     'account',
    'disable_account':     'account',
    'push_ioc':            'ioc',
    'close_incident_fp':   'incident',
}

# Actions that change state on a production asset. These require an explicit
# per-action feature flag in addition to the global gate.
DESTRUCTIVE_ACTIONS = ('isolate_device', 'revoke_sessions', 'disable_account')


# ── Schema ───────────────────────────────────────────────────────────────────

_TRIAGE_TABLE = '''
    CREATE TABLE IF NOT EXISTS incident_triage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        verdict TEXT,
        confidence INTEGER,
        evidence_grade TEXT,
        risk_score INTEGER,
        severity_assessment TEXT,
        suggested_classification TEXT,
        suggested_determination TEXT,
        summary TEXT,
        mitre TEXT,
        rca TEXT,
        recommended_actions TEXT,
        entity_reputations TEXT,
        investigation_trace TEXT,
        model TEXT,
        model_tier TEXT,
        routing_reason TEXT,
        source TEXT NOT NULL DEFAULT 'autonomous_triage',
        raw_response TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (incident_id) REFERENCES incidents(id)
    )
'''

_ACTIONS_TABLE = '''
    CREATE TABLE IF NOT EXISTS response_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        triage_id INTEGER,
        action_type TEXT NOT NULL,
        target_type TEXT,
        target_value TEXT,
        resolved_target_id TEXT,
        reason TEXT,
        status TEXT NOT NULL DEFAULT 'proposed',
        dry_run INTEGER NOT NULL DEFAULT 0,
        requested_by TEXT,
        decided_by TEXT,
        result_message TEXT,
        api_status_code INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        decided_at TIMESTAMP,
        executed_at TIMESTAMP,
        FOREIGN KEY (incident_id) REFERENCES incidents(id),
        FOREIGN KEY (triage_id) REFERENCES incident_triage(id)
    )
'''

_INDEXES = (
    'CREATE INDEX IF NOT EXISTS idx_triage_incident ON incident_triage(incident_id)',
    'CREATE INDEX IF NOT EXISTS idx_triage_created ON incident_triage(created_at)',
    'CREATE INDEX IF NOT EXISTS idx_triage_verdict ON incident_triage(verdict)',
    'CREATE INDEX IF NOT EXISTS idx_actions_incident ON response_actions(incident_id)',
    'CREATE INDEX IF NOT EXISTS idx_actions_status ON response_actions(status)',
    'CREATE INDEX IF NOT EXISTS idx_actions_created ON response_actions(created_at)',
)

# Columns added after the first release. Each entry is (table, column, ddl_type).
# Applied only when absent, so re-running the migration is free.
_ADDITIVE_COLUMNS: List[tuple] = [
    # ('incident_triage', 'example_column', 'TEXT'),
]


def init_triage_schema() -> None:
    """Create the triage/response tables and indexes if they do not exist."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(_TRIAGE_TABLE)
        cursor.execute(_ACTIONS_TABLE)
        for stmt in _INDEXES:
            cursor.execute(stmt)

        for table, column, ddl in _ADDITIVE_COLUMNS:
            existing = {r['name'] for r in cursor.execute(f'PRAGMA table_info({table})').fetchall()}
            if column not in existing:
                cursor.execute(f'ALTER TABLE {table} ADD COLUMN {column} {ddl}')
                log.info('🔧 Added column %s.%s', table, column)

        conn.commit()
        print('✅ Triage schema initialized')
    except Exception as exc:
        conn.rollback()
        log.error('❌ Triage schema migration failed: %s', exc)
        raise
    finally:
        conn.close()


# ── Incident lookup ──────────────────────────────────────────────────────────

def get_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    """Return the full incident dict from the incidents.data JSON column."""
    conn = get_connection()
    try:
        row = conn.execute(
            'SELECT data FROM incidents WHERE id = ?', (str(incident_id),)
        ).fetchone()
        if not row:
            return None
        return json.loads(row['data'])
    except Exception as exc:
        log.warning('⚠️  Incident lookup failed for %s: %s', incident_id, exc)
        return None
    finally:
        conn.close()


def get_incident_alerts(incident_id: str, limit: int = 25) -> List[Dict[str, Any]]:
    """Return alert dicts linked to an incident, newest first."""
    conn = get_connection()
    try:
        rows = conn.execute(
            'SELECT data FROM alerts WHERE incident_id = ? ORDER BY timestamp DESC LIMIT ?',
            (str(incident_id), int(limit)),
        ).fetchall()
        return [json.loads(r['data']) for r in rows]
    except Exception as exc:
        log.warning('⚠️  Alert lookup failed for %s: %s', incident_id, exc)
        return []
    finally:
        conn.close()


# ── Triage records ───────────────────────────────────────────────────────────

_JSON_TRIAGE_FIELDS = ('mitre', 'rca', 'recommended_actions',
                       'entity_reputations', 'investigation_trace')


def _hydrate_triage(row: Any) -> Dict[str, Any]:
    result = dict(row)
    for field in _JSON_TRIAGE_FIELDS:
        raw = result.get(field)
        if raw:
            try:
                result[field] = json.loads(raw)
            except (TypeError, ValueError):
                result[field] = None
    return result


def insert_triage(
    incident_id: str,
    verdict: Optional[str],
    confidence: Optional[int],
    evidence_grade: str,
    summary: Optional[str],
    *,
    risk_score: Optional[int] = None,
    severity_assessment: Optional[str] = None,
    suggested_classification: Optional[str] = None,
    suggested_determination: Optional[str] = None,
    mitre: Optional[Dict[str, Any]] = None,
    rca: Optional[Dict[str, Any]] = None,
    recommended_actions: Optional[List[str]] = None,
    entity_reputations: Optional[List[Dict[str, Any]]] = None,
    investigation_trace: Optional[Dict[str, Any]] = None,
    model: Optional[str] = None,
    model_tier: Optional[str] = None,
    routing_reason: Optional[str] = None,
    source: str = 'autonomous_triage',
    raw_response: Optional[str] = None,
) -> Optional[int]:
    """Persist a triage result. Returns the new row id, or None on failure."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            '''INSERT INTO incident_triage
               (incident_id, verdict, confidence, evidence_grade, risk_score,
                severity_assessment, suggested_classification, suggested_determination,
                summary, mitre, rca, recommended_actions, entity_reputations,
                investigation_trace, model, model_tier, routing_reason, source, raw_response)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                str(incident_id), verdict, confidence, evidence_grade, risk_score,
                severity_assessment, suggested_classification, suggested_determination,
                summary,
                json.dumps(mitre) if mitre else None,
                json.dumps(rca) if rca else None,
                json.dumps(recommended_actions) if recommended_actions else None,
                json.dumps(entity_reputations) if entity_reputations else None,
                json.dumps(investigation_trace) if investigation_trace else None,
                model, model_tier, routing_reason, source,
                (raw_response or '')[:20000] or None,
            ),
        )
        conn.commit()
        return cursor.lastrowid
    except Exception as exc:
        conn.rollback()
        log.error('❌ Triage insert failed for %s: %s', incident_id, exc)
        return None
    finally:
        conn.close()


def get_triage(incident_id: str) -> Optional[Dict[str, Any]]:
    """Return the most recent triage record for an incident."""
    conn = get_connection()
    try:
        row = conn.execute(
            '''SELECT * FROM incident_triage WHERE incident_id = ?
               ORDER BY created_at DESC, id DESC LIMIT 1''',
            (str(incident_id),),
        ).fetchone()
        return _hydrate_triage(row) if row else None
    finally:
        conn.close()


def get_triage_batch(incident_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Return {incident_id: latest triage} for a batch of incident ids."""
    if not incident_ids:
        return {}
    ids = [str(i) for i in incident_ids]
    conn = get_connection()
    try:
        placeholders = ','.join('?' for _ in ids)
        rows = conn.execute(
            f'''SELECT t.* FROM incident_triage t
                INNER JOIN (
                    SELECT incident_id, MAX(id) AS max_id
                    FROM incident_triage
                    WHERE incident_id IN ({placeholders})
                    GROUP BY incident_id
                ) latest ON t.id = latest.max_id''',
            ids,
        ).fetchall()
        return {r['incident_id']: _hydrate_triage(r) for r in rows}
    finally:
        conn.close()


def get_triage_stats(days: int = 30) -> Dict[str, Any]:
    """Coverage and verdict distribution for the dashboard."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        triaged = cur.execute(
            '''SELECT COUNT(DISTINCT incident_id) AS cnt FROM incident_triage
               WHERE created_at >= datetime('now', ?)''',
            (f'-{int(days)} days',),
        ).fetchone()['cnt']
        by_verdict = {
            r['verdict'] or 'Unknown': r['cnt']
            for r in cur.execute(
                '''SELECT verdict, COUNT(*) AS cnt FROM incident_triage
                   WHERE created_at >= datetime('now', ?) GROUP BY verdict''',
                (f'-{int(days)} days',),
            ).fetchall()
        }
        by_grade = {
            r['evidence_grade'] or 'unknown': r['cnt']
            for r in cur.execute(
                '''SELECT evidence_grade, COUNT(*) AS cnt FROM incident_triage
                   WHERE created_at >= datetime('now', ?) GROUP BY evidence_grade''',
                (f'-{int(days)} days',),
            ).fetchall()
        }
        actions = {
            r['status']: r['cnt']
            for r in cur.execute(
                '''SELECT status, COUNT(*) AS cnt FROM response_actions
                   WHERE created_at >= datetime('now', ?) GROUP BY status''',
                (f'-{int(days)} days',),
            ).fetchall()
        }
        return {
            'days': days,
            'incidents_triaged': triaged,
            'by_verdict': by_verdict,
            'by_evidence_grade': by_grade,
            'actions_by_status': actions,
        }
    finally:
        conn.close()


# ── Response actions ─────────────────────────────────────────────────────────

def create_response_action(
    incident_id: str,
    action_type: str,
    target_type: Optional[str],
    target_value: Optional[str],
    reason: Optional[str],
    *,
    triage_id: Optional[int] = None,
    requested_by: str = 'autonomous_triage',
) -> Optional[int]:
    """Record a PROPOSED action. This never executes anything."""
    if action_type not in ACTION_TYPES:
        log.warning('⚠️  Refusing to record unknown action type: %s', action_type)
        return None
    conn = get_connection()
    try:
        cursor = conn.execute(
            '''INSERT INTO response_actions
               (incident_id, triage_id, action_type, target_type, target_value,
                reason, status, requested_by)
               VALUES (?, ?, ?, ?, ?, ?, 'proposed', ?)''',
            (str(incident_id), triage_id, action_type, target_type,
             target_value, reason, requested_by),
        )
        conn.commit()
        return cursor.lastrowid
    except Exception as exc:
        conn.rollback()
        log.error('❌ Action insert failed for %s/%s: %s', incident_id, action_type, exc)
        return None
    finally:
        conn.close()


def get_response_action(action_id: int) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        row = conn.execute(
            'SELECT * FROM response_actions WHERE id = ?', (int(action_id),)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_response_actions(
    incident_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        query = 'SELECT * FROM response_actions WHERE 1=1'
        params: List[Any] = []
        if incident_id:
            query += ' AND incident_id = ?'
            params.append(str(incident_id))
        if status:
            query += ' AND status = ?'
            params.append(status)
        query += ' ORDER BY id DESC LIMIT ?'
        params.append(int(limit))
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def claim_response_action(action_id: int, decided_by: str) -> bool:
    """
    Atomically move a 'proposed' action to 'executing'.

    Returns True only for the caller that won the transition, so a double-clicked
    approve button cannot isolate a device twice.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            '''UPDATE response_actions
               SET status = 'executing', decided_by = ?, decided_at = ?
               WHERE id = ? AND status = 'proposed' ''',
            (decided_by, datetime.utcnow().isoformat(), int(action_id)),
        )
        conn.commit()
        return cursor.rowcount == 1
    except Exception as exc:
        conn.rollback()
        log.error('❌ Action claim failed for %s: %s', action_id, exc)
        return False
    finally:
        conn.close()


def finish_response_action(
    action_id: int,
    status: str,
    result_message: str,
    *,
    api_status_code: Optional[int] = None,
    resolved_target_id: Optional[str] = None,
    dry_run: bool = False,
) -> bool:
    """Write the real outcome of an executor back to the audit row."""
    if status not in ACTION_STATUSES:
        log.warning('⚠️  Invalid action status: %s', status)
        return False
    conn = get_connection()
    try:
        conn.execute(
            '''UPDATE response_actions
               SET status = ?, result_message = ?, api_status_code = ?,
                   resolved_target_id = COALESCE(?, resolved_target_id),
                   dry_run = ?, executed_at = ?
               WHERE id = ?''',
            (status, result_message[:2000], api_status_code, resolved_target_id,
             1 if dry_run else 0, datetime.utcnow().isoformat(), int(action_id)),
        )
        conn.commit()
        return True
    except Exception as exc:
        conn.rollback()
        log.error('❌ Action finalize failed for %s: %s', action_id, exc)
        return False
    finally:
        conn.close()


def reject_response_action(action_id: int, decided_by: str, note: str = '') -> bool:
    conn = get_connection()
    try:
        cursor = conn.execute(
            '''UPDATE response_actions
               SET status = 'rejected', decided_by = ?, decided_at = ?,
                   result_message = ?
               WHERE id = ? AND status = 'proposed' ''',
            (decided_by, datetime.utcnow().isoformat(),
             (note or 'Rejected by analyst')[:2000], int(action_id)),
        )
        conn.commit()
        return cursor.rowcount == 1
    except Exception as exc:
        conn.rollback()
        log.error('❌ Action reject failed for %s: %s', action_id, exc)
        return False
    finally:
        conn.close()


def has_recent_action(incident_id: str, action_type: str, target_value: str,
                      within_minutes: int = 60) -> bool:
    """
    Guard against duplicate proposals across repeated triage runs.
    Counts proposed/executing/executed/simulated — not rejected or failed.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            '''SELECT COUNT(*) AS cnt FROM response_actions
               WHERE incident_id = ? AND action_type = ?
                 AND IFNULL(target_value, '') = ?
                 AND status IN ('proposed', 'executing', 'executed', 'simulated')
                 AND created_at >= datetime('now', ?)''',
            (str(incident_id), action_type, target_value or '',
             f'-{int(within_minutes)} minutes'),
        ).fetchone()
        return bool(row['cnt'])
    finally:
        conn.close()
