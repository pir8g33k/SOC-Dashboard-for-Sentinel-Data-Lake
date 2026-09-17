"""
Gated incident response actions for SOC Dashboard.

Every action in here calls a real Microsoft API. Nothing runs without:

  1. RESPONSE_ACTIONS_ENABLED on (global kill switch, default OFF),
  2. the action's own RESPONSE_ALLOW_* flag on (default OFF),
  3. an explicit approval call from an admin route,
  4. RESPONSE_DRY_RUN off (default ON — dry runs validate and log, and are
     recorded with status 'simulated', never 'executed').

Design rules, learned from auditing a reference implementation that reported
success for containment it never performed:

  * An executor either performs the API call or records 'simulated'/'failed'.
    There is no code path that reports success without an HTTP 2xx.
  * The incident audit comment states the real outcome, including failures and
    dry runs.
  * Targets are resolved against the live directory / device inventory. An
    ambiguous or missing target fails the action; it is never guessed.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import requests

from config_manager import get_config
from database import update_incident_field
from triage_db import (
    DESTRUCTIVE_ACTIONS,
    claim_response_action,
    finish_response_action,
    get_response_action,
    reject_response_action,
)

log = logging.getLogger(__name__)

GRAPH_BASE = 'https://graph.microsoft.com/v1.0'
MDE_BASE = 'https://api.securitycenter.microsoft.com/api'
MDE_SCOPE = 'https://api.securitycenter.microsoft.com/.default'

HTTP_TIMEOUT = 30

_TRUTHY = ('true', '1', 'yes', 'on')

# Per-action feature flag names.
ACTION_FLAGS = {
    'isolate_device': 'RESPONSE_ALLOW_ISOLATE_DEVICE',
    'revoke_sessions': 'RESPONSE_ALLOW_REVOKE_SESSIONS',
    'disable_account': 'RESPONSE_ALLOW_DISABLE_ACCOUNT',
    'push_ioc': 'RESPONSE_ALLOW_PUSH_IOC',
    'close_incident_fp': 'RESPONSE_ALLOW_CLOSE_FP',
}

ACTION_LABELS = {
    'isolate_device': 'Isolate device (Defender for Endpoint)',
    'revoke_sessions': 'Revoke Entra ID sign-in sessions',
    'disable_account': 'Disable Entra ID account',
    'push_ioc': 'Push indicator to Sentinel threat intelligence',
    'close_incident_fp': 'Close incident as false positive',
}


def _flag(key: str, default: bool = False) -> bool:
    raw = get_config(key)
    if raw is None or raw == '':
        return default
    return str(raw).strip().lower() in _TRUTHY


def _dry_run() -> bool:
    """Dry run defaults to ON. It must be switched off deliberately."""
    return _flag('RESPONSE_DRY_RUN', True)


class ActionError(Exception):
    """Raised when an action cannot be performed. Message is analyst-safe."""


# ── Token helpers ────────────────────────────────────────────────────────────

def _graph_token() -> str:
    from fetch_live_data import get_graph_access_token
    token = get_graph_access_token()
    if not token:
        raise ActionError('Could not obtain a Microsoft Graph token')
    return token


def _mde_token() -> str:
    from fetch_live_data import get_graph_access_token
    token = get_graph_access_token(scope=MDE_SCOPE)
    if not token:
        raise ActionError('Could not obtain a Defender for Endpoint token')
    return token


def _api_error(resp: requests.Response, what: str) -> ActionError:
    """Log the provider detail, return a generic message for the API response."""
    detail = (resp.text or '')[:500]
    log.error('❌ %s failed: HTTP %s — %s', what, resp.status_code, detail)
    return ActionError(f'{what} failed with HTTP {resp.status_code}')


# ── Target resolution ────────────────────────────────────────────────────────

def resolve_device(name: str) -> Tuple[str, str]:
    """
    Resolve a device name to an MDE machine id.

    Returns (machine_id, resolved_name). Raises when there is no unique match —
    isolating the wrong host is worse than not isolating.
    """
    token = _mde_token()
    short = name.split('.')[0]
    # computerDnsName is the FQDN in MDE; match exact first, then prefix.
    url = f"{MDE_BASE}/machines?$filter=computerDnsName eq '{name}'&$select=id,computerDnsName,healthStatus"
    resp = requests.get(url, headers={'Authorization': f'Bearer {token}'}, timeout=HTTP_TIMEOUT)
    if not resp.ok:
        raise _api_error(resp, 'Device lookup')

    machines = resp.json().get('value') or []
    if not machines and short != name:
        url = (f"{MDE_BASE}/machines?$filter=startswith(computerDnsName,'{short}')"
               '&$select=id,computerDnsName,healthStatus')
        resp = requests.get(url, headers={'Authorization': f'Bearer {token}'},
                            timeout=HTTP_TIMEOUT)
        if not resp.ok:
            raise _api_error(resp, 'Device lookup')
        machines = resp.json().get('value') or []

    if not machines:
        raise ActionError(f'No Defender for Endpoint device matches "{name}"')
    if len(machines) > 1:
        names = ', '.join(m.get('computerDnsName', '?') for m in machines[:5])
        raise ActionError(f'"{name}" matches {len(machines)} devices ({names}) — resolve manually')

    machine = machines[0]
    return machine['id'], machine.get('computerDnsName', name)


def resolve_user(identifier: str) -> Tuple[str, str]:
    """
    Resolve an account name to an Entra ID object id.

    Graph incident evidence often carries a sAMAccountName rather than a UPN, so
    both are tried. Returns (object_id, userPrincipalName).
    """
    token = _graph_token()
    headers = {'Authorization': f'Bearer {token}',
               'ConsistencyLevel': 'eventual'}

    if '@' in identifier:
        resp = requests.get(
            f'{GRAPH_BASE}/users/{identifier}?$select=id,userPrincipalName,accountEnabled',
            headers=headers, timeout=HTTP_TIMEOUT,
        )
        if resp.ok:
            body = resp.json()
            return body['id'], body.get('userPrincipalName', identifier)
        if resp.status_code != 404:
            raise _api_error(resp, 'User lookup')

    safe = identifier.replace("'", "''")
    filter_expr = (f"userPrincipalName eq '{safe}' or onPremisesSamAccountName eq '{safe}' "
                   f"or mailNickname eq '{safe}'")
    resp = requests.get(
        f'{GRAPH_BASE}/users?$filter={requests.utils.quote(filter_expr)}'
        '&$select=id,userPrincipalName,accountEnabled',
        headers=headers, timeout=HTTP_TIMEOUT,
    )
    if not resp.ok:
        raise _api_error(resp, 'User lookup')

    users = resp.json().get('value') or []
    if not users:
        raise ActionError(f'No Entra ID user matches "{identifier}"')
    if len(users) > 1:
        upns = ', '.join(u.get('userPrincipalName', '?') for u in users[:5])
        raise ActionError(f'"{identifier}" matches {len(users)} users ({upns}) — resolve manually')

    return users[0]['id'], users[0].get('userPrincipalName', identifier)


_MD5 = re.compile(r'^[a-fA-F0-9]{32}$')
_SHA1 = re.compile(r'^[a-fA-F0-9]{40}$')
_SHA256 = re.compile(r'^[a-fA-F0-9]{64}$')


def classify_ioc(target_type: str, value: str) -> str:
    """Map an incident entity to one of ioc_upload's STIX types."""
    value = value.strip()
    if target_type == 'ip':
        return 'ipv6-addr' if ':' in value else 'ipv4-addr'
    if target_type == 'file':
        if _SHA256.match(value):
            return 'file:sha256'
        if _SHA1.match(value):
            return 'file:sha1'
        if _MD5.match(value):
            return 'file:md5'
        raise ActionError(f'"{value}" is not a recognised file hash')
    if target_type == 'url':
        return 'url' if value.startswith(('http://', 'https://', 'ftp://')) else 'domain-name'
    raise ActionError(f'Cannot build an indicator from a {target_type} entity')


# ── Executors ────────────────────────────────────────────────────────────────
# Each returns (result_message, http_status, resolved_target_id) or raises
# ActionError. They are only ever called by execute_response_action().

def _exec_isolate_device(action: Dict[str, Any], dry_run: bool) -> Tuple[str, Optional[int], str]:
    name = action['target_value']
    machine_id, resolved_name = resolve_device(name)
    isolation_type = (get_config('RESPONSE_ISOLATION_TYPE') or 'Full').strip()
    if isolation_type not in ('Full', 'Selective'):
        isolation_type = 'Full'

    if dry_run:
        return (f'DRY RUN — would isolate "{resolved_name}" (machine {machine_id}) '
                f'with {isolation_type} isolation. No API call made.'), None, machine_id

    body = {
        'Comment': (action.get('reason') or 'Contained via SOC Dashboard triage')[:500],
        'IsolationType': isolation_type,
    }
    resp = requests.post(
        f'{MDE_BASE}/machines/{machine_id}/isolate',
        headers={'Authorization': f'Bearer {_mde_token()}', 'Content-Type': 'application/json'},
        json=body, timeout=HTTP_TIMEOUT,
    )
    if not resp.ok:
        raise _api_error(resp, f'Device isolation for {resolved_name}')

    machine_action_id = ''
    try:
        machine_action_id = resp.json().get('id', '')
    except ValueError:
        pass
    return (f'{isolation_type} isolation requested for "{resolved_name}" '
            f'(machine {machine_id}, MDE action {machine_action_id or "n/a"}). '
            'Isolation is asynchronous — confirm in the Defender portal.'), resp.status_code, machine_id


def _exec_revoke_sessions(action: Dict[str, Any], dry_run: bool) -> Tuple[str, Optional[int], str]:
    user_id, upn = resolve_user(action['target_value'])

    if dry_run:
        return (f'DRY RUN — would revoke all sign-in sessions for {upn} '
                f'(object {user_id}). No API call made.'), None, user_id

    resp = requests.post(
        f'{GRAPH_BASE}/users/{user_id}/revokeSignInSessions',
        headers={'Authorization': f'Bearer {_graph_token()}', 'Content-Type': 'application/json'},
        timeout=HTTP_TIMEOUT,
    )
    if not resp.ok:
        raise _api_error(resp, f'Session revocation for {upn}')
    return (f'Refresh tokens and sign-in sessions revoked for {upn} (object {user_id}). '
            'Propagation can take a few minutes.'), resp.status_code, user_id


def _exec_disable_account(action: Dict[str, Any], dry_run: bool) -> Tuple[str, Optional[int], str]:
    user_id, upn = resolve_user(action['target_value'])

    if dry_run:
        return (f'DRY RUN — would set accountEnabled=false for {upn} '
                f'(object {user_id}). No API call made.'), None, user_id

    resp = requests.patch(
        f'{GRAPH_BASE}/users/{user_id}',
        headers={'Authorization': f'Bearer {_graph_token()}', 'Content-Type': 'application/json'},
        json={'accountEnabled': False}, timeout=HTTP_TIMEOUT,
    )
    if not resp.ok:
        raise _api_error(resp, f'Account disable for {upn}')
    return (f'Account {upn} (object {user_id}) disabled in Entra ID. '
            'Re-enable from the Entra portal once the investigation closes.'), resp.status_code, user_id


def _exec_push_ioc(action: Dict[str, Any], dry_run: bool) -> Tuple[str, Optional[int], str]:
    value = action['target_value']
    ioc_type = classify_ioc(action.get('target_type') or '', value)

    from ioc_upload import upload_single_ioc, validate_ioc
    ok, err = validate_ioc(ioc_type, value)
    if not ok:
        raise ActionError(f'Indicator rejected: {err}')

    confidence = 75
    try:
        confidence = max(0, min(100, int(get_config('RESPONSE_IOC_CONFIDENCE') or 75)))
    except (TypeError, ValueError):
        pass

    if dry_run:
        return (f'DRY RUN — would publish {ioc_type} indicator "{value}" to Sentinel TI '
                f'at confidence {confidence}. No API call made.'), None, value

    description = (f"Incident {action['incident_id']}: "
                   f"{action.get('reason') or 'observed during autonomous triage'}")[:500]
    response = upload_single_ioc(
        ioc_type=ioc_type,
        value=value,
        confidence=confidence,
        description=description,
        tags=['SOC-Dashboard', 'Autonomous-Triage', f"Incident-{action['incident_id']}"],
        source='SOC Dashboard Triage',
    )
    indicator_name = (response or {}).get('name', 'created')
    return (f'{ioc_type} indicator "{value}" published to Sentinel threat intelligence '
            f'(indicator {indicator_name}).'), 200, value


def _exec_close_incident_fp(action: Dict[str, Any], dry_run: bool) -> Tuple[str, Optional[int], str]:
    incident_id = str(action['incident_id'])
    if not incident_id.isdigit():
        raise ActionError('Only Graph incidents (numeric id) can be closed')

    determination = (get_config('RESPONSE_FP_DETERMINATION') or 'notMalicious').strip()
    if determination not in ('notMalicious', 'securityTesting', 'securityPersonnel', 'other'):
        determination = 'notMalicious'

    if dry_run:
        return (f'DRY RUN — would close incident {incident_id} as falsePositive '
                f'/ {determination}. No API call made.'), None, incident_id

    from fetch_live_data import graph_patch_incident
    graph_patch_incident(incident_id, {
        'status': 'resolved',
        'classification': 'falsePositive',
        'determination': determination,
        'customTags': ['ClosedByAutonomousTriage'],
    })
    update_incident_field(incident_id, 'status', 'Closed')
    update_incident_field(incident_id, 'classification', 'falsePositive')
    update_incident_field(incident_id, 'determination', determination)
    return (f'Incident {incident_id} closed as falsePositive / {determination}.'), 200, incident_id


_EXECUTORS = {
    'isolate_device': _exec_isolate_device,
    'revoke_sessions': _exec_revoke_sessions,
    'disable_account': _exec_disable_account,
    'push_ioc': _exec_push_ioc,
    'close_incident_fp': _exec_close_incident_fp,
}


# ── Gating ───────────────────────────────────────────────────────────────────

def check_gates(action_type: str) -> Tuple[bool, str]:
    """Return (allowed, reason). Checked again at execution time, not just at UI time."""
    if action_type not in _EXECUTORS:
        return False, f'Unsupported action type: {action_type}'
    if not _flag('RESPONSE_ACTIONS_ENABLED', False):
        return False, 'Response actions are disabled (RESPONSE_ACTIONS_ENABLED is off)'
    flag = ACTION_FLAGS[action_type]
    if not _flag(flag, False):
        return False, f'{ACTION_LABELS[action_type]} is not permitted ({flag} is off)'
    return True, ''


def describe_gates() -> Dict[str, Any]:
    """Expose the current gate state so the UI can grey out what it cannot do."""
    global_on = _flag('RESPONSE_ACTIONS_ENABLED', False)
    return {
        'response_actions_enabled': global_on,
        'dry_run': _dry_run(),
        'actions': {
            atype: {
                'label': ACTION_LABELS[atype],
                'allowed': global_on and _flag(flag, False),
                'flag': flag,
                'destructive': atype in DESTRUCTIVE_ACTIONS,
            }
            for atype, flag in ACTION_FLAGS.items()
        },
    }


# ── Audit trail ──────────────────────────────────────────────────────────────

def _post_audit_comment(incident_id: str, action_type: str, status: str,
                        message: str, approver: str) -> None:
    """
    Record what actually happened on the incident. Posted for success, failure
    and dry run alike — a silent failure is how audit trails start lying.
    """
    if not str(incident_id).isdigit():
        return
    headline = {
        'executed': 'RESPONSE ACTION EXECUTED',
        'failed': 'RESPONSE ACTION FAILED',
        'simulated': 'RESPONSE ACTION DRY RUN (not executed)',
        'rejected': 'RESPONSE ACTION REJECTED',
    }.get(status, f'RESPONSE ACTION {status.upper()}')

    comment = (
        f'[SOC Dashboard - {headline}]\n'
        f'Action: {ACTION_LABELS.get(action_type, action_type)}\n'
        f'Approved by: {approver}\n'
        f'Result: {message}'
    )
    try:
        from fetch_live_data import graph_post_comment
        graph_post_comment(str(incident_id), comment[:1000])
    except Exception as exc:
        log.warning('⚠️  Audit comment post failed for incident %s: %s', incident_id, exc)


# ── Public entry points ──────────────────────────────────────────────────────

def execute_response_action(action_id: int, approver: str,
                            note: str = '') -> Dict[str, Any]:
    """
    Execute a previously proposed action after human approval.

    Call this only from an admin-authenticated route. Returns
    {'success', 'status', 'message', 'action'}.
    """
    action = get_response_action(action_id)
    if not action:
        return {'success': False, 'status': None, 'message': 'Action not found'}

    if action['status'] != 'proposed':
        return {'success': False, 'status': action['status'],
                'message': f"Action is already {action['status']} — nothing to do"}

    action_type = action['action_type']
    allowed, reason = check_gates(action_type)
    if not allowed:
        return {'success': False, 'status': 'proposed', 'message': reason}

    if not claim_response_action(action_id, approver):
        current = get_response_action(action_id) or {}
        return {'success': False, 'status': current.get('status'),
                'message': 'Action was already claimed by another request'}

    dry_run = _dry_run()
    executor = _EXECUTORS[action_type]

    try:
        message, http_status, resolved_id = executor(action, dry_run)
        status = 'simulated' if dry_run else 'executed'
        if note:
            message = f'{message} | Analyst note: {note[:200]}'
        finish_response_action(action_id, status, message,
                               api_status_code=http_status,
                               resolved_target_id=resolved_id,
                               dry_run=dry_run)
        _post_audit_comment(action['incident_id'], action_type, status, message, approver)
        print(f"{'🧪' if dry_run else '⚡'} Action {action_id} ({action_type}) {status}: {message[:120]}")
        return {'success': True, 'status': status, 'message': message,
                'dry_run': dry_run, 'action': get_response_action(action_id)}

    except ActionError as exc:
        message = str(exc)
        finish_response_action(action_id, 'failed', message, dry_run=dry_run)
        _post_audit_comment(action['incident_id'], action_type, 'failed', message, approver)
        log.warning('❌ Action %s (%s) failed: %s', action_id, action_type, message)
        return {'success': False, 'status': 'failed', 'message': message}

    except Exception:
        # Unexpected failure: record it, surface a generic message (repo rule:
        # never return str(e) to the client).
        log.exception('❌ Action %s (%s) raised', action_id, action_type)
        message = 'Action failed with an unexpected error — check server logs'
        finish_response_action(action_id, 'failed', message, dry_run=dry_run)
        _post_audit_comment(action['incident_id'], action_type, 'failed', message, approver)
        return {'success': False, 'status': 'failed', 'message': message}


def reject_action(action_id: int, approver: str, note: str = '') -> Dict[str, Any]:
    """Decline a proposed action and record who declined it."""
    action = get_response_action(action_id)
    if not action:
        return {'success': False, 'message': 'Action not found'}
    if action['status'] != 'proposed':
        return {'success': False, 'message': f"Action is already {action['status']}"}

    if not reject_response_action(action_id, approver, note):
        return {'success': False, 'message': 'Could not reject — action state changed'}

    _post_audit_comment(action['incident_id'], action['action_type'], 'rejected',
                        note or 'No reason given', approver)
    return {'success': True, 'message': 'Action rejected',
            'action': get_response_action(action_id)}


def auto_execute_eligible(incident_id: str, triage: Dict[str, Any],
                          approver: str = 'auto-close policy') -> List[Dict[str, Any]]:
    """
    The only automatic execution path: closing a high-confidence false positive.

    Requires TRIAGE_AUTO_CLOSE_FP_ENABLED, a FalsePositive verdict at or above
    TRIAGE_AUTO_CLOSE_MIN_CONFIDENCE, and evidence_grade == 'verified'. Never
    touches a destructive action, whatever the confidence.
    """
    if not _flag('TRIAGE_AUTO_CLOSE_FP_ENABLED', False):
        return []
    if triage.get('verdict') != 'FalsePositive':
        return []
    if triage.get('evidence_grade') != 'verified':
        log.info('⏭️  Auto-close skipped for %s: evidence grade is %s',
                 incident_id, triage.get('evidence_grade'))
        return []

    try:
        floor = int(get_config('TRIAGE_AUTO_CLOSE_MIN_CONFIDENCE') or 90)
    except (TypeError, ValueError):
        floor = 90
    if int(triage.get('confidence') or 0) < floor:
        return []

    results = []
    for action in triage.get('actions') or []:
        if action.get('action_type') != 'close_incident_fp':
            continue
        results.append(execute_response_action(action['id'], approver))
    return results
