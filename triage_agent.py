"""
Autonomous incident triage for SOC Dashboard.

Pipeline per incident:

  1. Route to a model tier based on incident shape (cost control).
  2. Run a deterministic, version-controlled KQL evidence pack against Log
     Analytics (triage_queries/). The model reasons over retrieved rows; it does
     not improvise its own retrieval.
  3. Ask the agent for a verdict under a strict output contract that includes
     four verdict gates — baseline, alternative hypotheses, attribution and
     negative findings.
  4. Grade how grounded the answer is, and downgrade it if it is not.
  5. Record containment actions as PROPOSALS. Nothing is executed here; see
     response_actions.py.

The controls exist because an ungoverned triage agent fails in a specific way:
it produces a confident verdict from an empty query result. Each control closes
one route to that outcome.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from config_manager import get_config

import triage_db
from triage_db import (
    ACTION_TYPES,
    DESTRUCTIVE_ACTIONS,
    create_response_action,
    get_incident_alerts,
    get_incident_by_id,
    has_recent_action,
    insert_triage,
)

log = logging.getLogger(__name__)

# ── Config helpers ───────────────────────────────────────────────────────────

_TRUTHY = ('true', '1', 'yes', 'on')


def _flag(key: str, default: bool = False) -> bool:
    raw = get_config(key)
    if raw is None or raw == '':
        return default
    return str(raw).strip().lower() in _TRUTHY


def _int_config(key: str, default: int) -> int:
    try:
        return int(str(get_config(key) or default).strip())
    except (TypeError, ValueError):
        return default


# ── Vocabulary ───────────────────────────────────────────────────────────────

VERDICT_TO_CLASSIFICATION = {
    'TruePositive': 'truePositive',
    'FalsePositive': 'falsePositive',
    'BenignPositive': 'informationalExpectedActivity',
    'Undetermined': 'unknown',
}

VALID_DETERMINATIONS = {
    'unknown', 'apt', 'malware', 'securityPersonnel', 'securityTesting',
    'unwantedSoftware', 'other', 'multiStagedAttack', 'compromisedAccount',
    'phishing', 'maliciousUserActivity', 'notMalicious', 'notEnoughData',
}

_VERDICT_ALIASES = {
    'true positive': 'TruePositive', 'truepositive': 'TruePositive',
    'tp': 'TruePositive', 'malicious': 'TruePositive',
    'false positive': 'FalsePositive', 'falsepositive': 'FalsePositive',
    'fp': 'FalsePositive',
    'benign positive': 'BenignPositive', 'benignpositive': 'BenignPositive',
    'benign': 'BenignPositive', 'expected activity': 'BenignPositive',
    'informationalexpectedactivity': 'BenignPositive',
    'undetermined': 'Undetermined', 'unknown': 'Undetermined',
    'inconclusive': 'Undetermined',
}

_ENTITY_TYPE_MAP = {
    'device': 'device', 'host': 'device', 'machine': 'device', 'deviceevidence': 'device',
    'useraccount': 'account', 'account': 'account', 'user': 'account',
    'mailbox': 'account', 'mailboxconfiguration': 'account',
    'ip': 'ip', 'ipaddress': 'ip',
    'file': 'file', 'process': 'file',
    'url': 'url', 'domain': 'url', 'domainname': 'url',
}

_ACTION_TARGET_TYPES = {
    'isolate_device': ('device',),
    'revoke_sessions': ('account',),
    'disable_account': ('account',),
    'push_ioc': ('ip', 'file', 'url'),
    'close_incident_fp': ('incident',),
}

# The four gates adopted from the security-investigator investigation skills.
VERDICT_GATES = ('BASELINE', 'ALTERNATIVES', 'ATTRIBUTION', 'NEGATIVE FINDINGS')


def normalise_entity_type(raw: Optional[str]) -> str:
    return _ENTITY_TYPE_MAP.get((raw or '').strip().lower(),
                                (raw or 'unknown').strip().lower())


def normalise_verdict(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    key = raw.strip().strip('*`_').lower()
    if key in _VERDICT_ALIASES:
        return _VERDICT_ALIASES[key]
    for alias, verdict in _VERDICT_ALIASES.items():
        if key.startswith(alias):
            return verdict
    return None


# ── Defanging ────────────────────────────────────────────────────────────────

_IP_IN_TEXT = re.compile(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b')
_URL_SCHEME = re.compile(r'\b(http|https|ftp)://', re.IGNORECASE)
_DOMAIN_IN_TEXT = re.compile(
    r'\b([a-zA-Z0-9\-]{1,63})\.((?:com|net|org|io|ru|cn|top|xyz|info|biz|cc|su|tk|onion))\b'
)

_PRIVATE_IP = re.compile(r'^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)')


def defang(text: Optional[str]) -> str:
    """
    Neutralise indicators in analyst-facing output so a report cannot be
    click-through weaponised. Private addresses are left readable.
    """
    if not text:
        return ''
    out = _URL_SCHEME.sub(lambda m: m.group(1).replace('t', 'x') + '://', text)

    def _ip(match: re.Match) -> str:
        value = match.group(0)
        if _PRIVATE_IP.match(value):
            return value
        return value.replace('.', '[.]')

    out = _IP_IN_TEXT.sub(_ip, out)
    out = _DOMAIN_IN_TEXT.sub(lambda m: f'{m.group(1)}[.]{m.group(2)}', out)
    return out


# ── Model-tier routing ───────────────────────────────────────────────────────

def select_model_tier(incident: Dict[str, Any]) -> Dict[str, str]:
    """
    Choose the deployment for this incident.

    TRIAGE_ROUTING_MODE: hybrid (default) | always_fast | always_deep.
    Both tier keys fall back to FOUNDRY_DEPLOYMENT, so this is safe to enable
    before a second deployment exists.
    """
    base = get_config('FOUNDRY_DEPLOYMENT') or ''
    fast = get_config('FOUNDRY_DEPLOYMENT_FAST') or base
    deep = get_config('FOUNDRY_DEPLOYMENT_DEEP') or base
    mode = (get_config('TRIAGE_ROUTING_MODE') or 'hybrid').strip().lower()

    if mode == 'always_fast':
        return {'deployment': fast, 'tier': 'fast', 'reason': 'Routing mode forced to always_fast'}
    if mode == 'always_deep':
        return {'deployment': deep, 'tier': 'deep', 'reason': 'Routing mode forced to always_deep'}

    severity = str(incident.get('severity') or 'Medium').strip().lower()
    alert_count = int(incident.get('alertCount') or 0)
    techniques = incident.get('mitreTechniques') or []

    if severity in ('low', 'informational'):
        return {'deployment': fast, 'tier': 'fast',
                'reason': f'{severity.capitalize()} severity — routine triage'}
    if severity in ('high', 'critical'):
        return {'deployment': deep, 'tier': 'deep',
                'reason': f'{severity.capitalize()} severity — deep reasoning'}
    if alert_count >= 2:
        return {'deployment': deep, 'tier': 'deep',
                'reason': f'Correlated multi-alert incident ({alert_count} alerts)'}
    if len(techniques) >= 2:
        return {'deployment': deep, 'tier': 'deep',
                'reason': f'Multi-technique incident ({len(techniques)} MITRE techniques)'}
    return {'deployment': fast, 'tier': 'fast',
            'reason': 'Single-alert medium severity — routine triage'}


# ── Prompt contract ──────────────────────────────────────────────────────────

TRIAGE_CONTRACT = """\
You are performing formal Tier-2 triage on one incident.

The EVIDENCE section below contains the results of a fixed set of KQL queries
already executed against this tenant's Sentinel workspace. Reason from those
rows. Use your Sentinel and Defender tools only to fill gaps the evidence leaves
open (device detail, file prevalence, Defender-side alert context).

Rules that override everything else:
  * A query returning zero rows is a CONFIRMED NEGATIVE FINDING, not an absence
    of information. Say what was checked and found clean.
  * A query marked QUERY FAILED means that evidence is UNAVAILABLE. Never treat
    a failed query as a clean result.
  * Never state a value you did not read from evidence or a tool result. Where
    data is missing, write "could not be verified".
  * Never describe behaviour as anomalous, unusual or suspicious without citing
    the baseline you compared it against.

Reply using EXACTLY the section headings below, in this order, as plain text.

## VERDICT
One of: TruePositive | FalsePositive | BenignPositive | Undetermined

## CONFIDENCE
Integer 0-100. Confidence reflects evidence coverage, not writing fluency.
If the evidence needed for your verdict failed or was unavailable, stay below 40
and set the verdict to Undetermined.

## DETERMINATION
One of: apt | malware | securityPersonnel | securityTesting | unwantedSoftware |
multiStagedAttack | compromisedAccount | phishing | maliciousUserActivity |
notMalicious | notEnoughData | other | unknown

## RISK SCORE
Integer 1-100.

## SEVERITY ASSESSMENT
One of: Critical | High | Medium | Low | Informational

## EXECUTIVE SUMMARY
2-3 paragraphs: what happened, what you verified, business impact.

## EVIDENCE
One finding per line, each citing the query id or tool it came from:
  - [E4-AccountSigninBaseline] 312 sign-ins, 289 failures, 1 source IP
  - [GetDefenderMachine] device is onboarded, risk score high
Write "- [none] No supporting evidence retrieved" if that is the case.

## VERDICT GATES
Answer all four. A gate you cannot satisfy must say so explicitly.
BASELINE: the 14-30 day baseline you compared against, and what it showed.
ALTERNATIVES: the benign explanations you considered, and for each whether the
  evidence eliminates it or leaves it unresolved.
ATTRIBUTION: the evidence tying this activity to the entity you are naming —
  not merely that the entity appears in the alert.
NEGATIVE FINDINGS: what you checked and found clean, including zero-row queries.

## MITRE
Tactics: comma-separated tactic names
Techniques: comma-separated technique IDs

## ROOT CAUSE
Patient zero: first compromised identity or device, or "Not established"
Initial access vector: mechanism, or "Not established"
Kill chain: one stage per line as "stage | technique | what was observed"
Blast radius: identities, devices and assets confirmed affected

## RECOMMENDED ACTIONS
Numbered list for the analyst, most urgent first.

## CAPA
Numbered list of corrective and preventive changes (policy, config, detection).

## ENTITY REPUTATIONS
- [entity name] ([type]): assessment grounded in the evidence above

## PROPOSED ACTIONS
Zero or more machine-executable containment requests, one per line, EXACTLY:
  ACTION: <action_type> | target: <entity name> | reason: <one line>
Permitted action_type values: isolate_device, revoke_sessions, disable_account,
push_ioc, close_incident_fp.
Constraints:
  - Only name entities present in the incident data above.
  - Propose nothing unless the verdict is TruePositive with confidence >= 70, or
    FalsePositive with confidence >= 90 (close_incident_fp only).
  - Write "ACTION: none" when no automated action is warranted.
These are proposals for human approval. Do not attempt to perform them yourself.
"""


def _entity_lines(entities: List[Dict[str, Any]], limit: int = 40) -> str:
    lines = []
    for entity in entities[:limit]:
        etype = normalise_entity_type(entity.get('type'))
        name = entity.get('name') or '?'
        verdict = entity.get('verdict') or 'unknown'
        extra = f", sha256: {entity['sha256']}" if entity.get('sha256') else ''
        lines.append(f'  - {etype}: {name} (verdict: {verdict}{extra})')
    return '\n'.join(lines)


def build_triage_prompt(
    incident: Dict[str, Any],
    alerts: Optional[List[Dict[str, Any]]] = None,
    evidence_text: str = '',
) -> str:
    """Assemble incident context, retrieved evidence, and the output contract."""
    entities = incident.get('entities') or []
    techniques = incident.get('mitreTechniques') or []
    alerts = alerts or []

    parts = [
        '# INCIDENT',
        f"Incident ID: {incident.get('id')}",
        f"Title: {incident.get('title')}",
        f"Severity: {incident.get('severity')}",
        f"Status: {incident.get('status')}",
        f"Created: {incident.get('createdTime')}",
        f"Alert count: {incident.get('alertCount')}",
    ]
    if incident.get('assignedTo'):
        parts.append(f"Assigned to: {incident.get('assignedTo')}")

    if entities:
        parts.append('Entities on this incident (the ONLY entities you may target):')
        parts.append(_entity_lines(entities))
    else:
        parts.append('Entities on this incident: none recorded.')

    if techniques:
        parts.append(f"MITRE techniques from alerts: {', '.join(techniques[:25])}")

    if alerts:
        parts.append('Alerts:')
        for alert in alerts[:10]:
            parts.append(
                f"  - [{alert.get('severity')}] {alert.get('title')} "
                f"({alert.get('product')} / {alert.get('detectionSource')}) "
                f"at {alert.get('timestamp')}"
            )

    parts.append('')
    parts.append('# EVIDENCE (pre-executed KQL, this tenant)')
    parts.append(evidence_text or 'No deterministic evidence was retrieved.')
    parts.append('')
    return '\n'.join(parts) + '\n' + TRIAGE_CONTRACT


# ── Response parsing ─────────────────────────────────────────────────────────

def _section(text: str, heading: str) -> Optional[str]:
    match = re.search(rf'##\s*{heading}\s*\n+(.*?)(?=\n##\s|\Z)',
                      text, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else None


def _numbered_list(body: Optional[str]) -> List[str]:
    items = []
    for line in (body or '').split('\n'):
        line = line.strip()
        if not line or line.startswith('...'):
            continue
        line = re.sub(r'^[\-\*•]\s*', '', line)
        line = re.sub(r'^\d+[\.\)]\s*', '', line).strip()
        if line:
            items.append(line)
    return items


def _first_int(body: Optional[str], lo: int, hi: int) -> Optional[int]:
    match = re.search(r'\d{1,3}', body or '')
    return max(lo, min(hi, int(match.group(0)))) if match else None


def _parse_kill_chain(body: str) -> List[Dict[str, str]]:
    stages = []
    for line in body.split('\n'):
        line = re.sub(r'^[\-\*•]\s*', '', line.strip())
        if not line or '|' not in line:
            continue
        bits = [b.strip() for b in line.split('|')]
        if len(bits) >= 3:
            stages.append({'stage': bits[0], 'technique': bits[1], 'observed': bits[2]})
    return stages


def _parse_root_cause(body: Optional[str]) -> Dict[str, Any]:
    rca: Dict[str, Any] = {'patient_zero': None, 'initial_access_vector': None,
                           'kill_chain': [], 'blast_radius': None}
    if not body:
        return rca

    def _field(label: str) -> Optional[str]:
        match = re.search(rf'{label}\s*:\s*(.+)', body, re.IGNORECASE)
        return match.group(1).strip() if match else None

    rca['patient_zero'] = _field('Patient zero')
    rca['initial_access_vector'] = _field('Initial access vector')
    rca['blast_radius'] = _field('Blast radius')

    chain = re.search(r'Kill chain\s*:\s*\n?(.*?)(?=\n\s*Blast radius\s*:|\Z)',
                      body, re.IGNORECASE | re.DOTALL)
    if chain:
        rca['kill_chain'] = _parse_kill_chain(chain.group(1))
    return rca


def _parse_mitre(body: Optional[str]) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {'tactics': [], 'techniques': []}
    for label, key in (('Tactics', 'tactics'), ('Techniques', 'techniques')):
        match = re.search(rf'{label}\s*:\s*(.+)', body or '', re.IGNORECASE)
        if match:
            result[key] = [v.strip() for v in match.group(1).split(',') if v.strip()]
    return result


def _parse_evidence(body: Optional[str]) -> List[Dict[str, str]]:
    findings = []
    for line in (body or '').split('\n'):
        line = re.sub(r'^[\-\*•]\s*', '', line.strip())
        if not line:
            continue
        match = re.match(r'^\[([^\]]*)\]\s*(.+)$', line)
        if match:
            findings.append({'source': match.group(1).strip() or 'unsourced',
                             'finding': match.group(2).strip()})
        else:
            findings.append({'source': 'unsourced', 'finding': line})
    return findings


def _parse_verdict_gates(body: Optional[str]) -> Dict[str, str]:
    """Split the VERDICT GATES block into its four labelled answers."""
    gates: Dict[str, str] = {}
    if not body:
        return gates
    labels = '|'.join(re.escape(g) for g in VERDICT_GATES)
    for match in re.finditer(rf'({labels})\s*:\s*(.*?)(?=\n\s*(?:{labels})\s*:|\Z)',
                             body, re.IGNORECASE | re.DOTALL):
        gates[match.group(1).upper()] = match.group(2).strip()
    return gates


def _parse_entity_reputations(body: Optional[str]) -> List[Dict[str, str]]:
    reputations = []
    for line in (body or '').split('\n'):
        line = re.sub(r'^[\-\*•]\s*', '', line.strip())
        if not line or line.startswith('...'):
            continue
        match = re.match(r'^\[?(.+?)\]?\s*\(([^)]+)\)\s*:\s*(.+)$', line)
        if match:
            reputations.append({'entity_name': match.group(1).strip(),
                                'entity_type': normalise_entity_type(match.group(2)),
                                'details': match.group(3).strip()})
        else:
            reputations.append({'entity_name': line, 'entity_type': 'unknown', 'details': ''})
    return reputations


_ACTION_LINE = re.compile(
    r'ACTION\s*:\s*(?P<type>[a-z_]+)\s*\|\s*target\s*:\s*(?P<target>[^|]+?)'
    r'(?:\s*\|\s*reason\s*:\s*(?P<reason>.+))?$',
    re.IGNORECASE,
)


def _parse_proposed_actions(body: Optional[str]) -> List[Dict[str, str]]:
    actions = []
    for line in (body or '').split('\n'):
        line = re.sub(r'^[\-\*•]\s*', '', line.strip())
        if not line or re.match(r'^ACTION\s*:\s*none\b', line, re.IGNORECASE):
            continue
        match = _ACTION_LINE.match(line)
        if not match:
            continue
        action_type = match.group('type').strip().lower()
        if action_type not in ACTION_TYPES:
            log.info('⏭️  Dropped unsupported proposed action: %s', action_type)
            continue
        actions.append({'action_type': action_type,
                        'target_value': match.group('target').strip().strip('`"\''),
                        'reason': (match.group('reason') or '').strip()})
    return actions


def parse_triage_response(text: str) -> Dict[str, Any]:
    """Convert a contract-formatted agent answer into a structured triage dict."""
    determination = (_section(text, 'DETERMINATION') or '').strip().strip('*`_')
    determination = determination.split('\n')[0].strip()
    if determination not in VALID_DETERMINATIONS:
        determination = 'unknown'

    severity = (_section(text, r'SEVERITY\s*ASSESSMENT') or '').strip().split('\n')[0]
    severity = severity.strip('*`_ ').capitalize() or None

    return {
        'verdict': normalise_verdict(_section(text, 'VERDICT')),
        'confidence': _first_int(_section(text, 'CONFIDENCE'), 0, 100),
        'suggested_determination': determination,
        'risk_score': _first_int(_section(text, r'RISK\s*SCORE'), 1, 100),
        'severity_assessment': severity,
        'summary': _section(text, r'EXECUTIVE\s*SUMMARY'),
        'evidence': _parse_evidence(_section(text, 'EVIDENCE')),
        'verdict_gates': _parse_verdict_gates(_section(text, r'VERDICT\s*GATES')),
        'mitre': _parse_mitre(_section(text, 'MITRE')),
        'rca': _parse_root_cause(_section(text, r'ROOT\s*CAUSE')),
        'recommended_actions': _numbered_list(_section(text, r'RECOMMENDED\s*ACTIONS')),
        'capa': _numbered_list(_section(text, 'CAPA')),
        'entity_reputations': _parse_entity_reputations(_section(text, r'ENTITY\s*REPUTATIONS?')),
        'proposed_actions': _parse_proposed_actions(_section(text, r'PROPOSED\s*ACTIONS')),
    }


# ── Verdict gates ────────────────────────────────────────────────────────────

_GATE_MIN_CHARS = 40
_GATE_EMPTY = re.compile(
    r'^(n/?a|none|not applicable|not assessed|not done|todo|tbd|\-+|unknown)\.?$',
    re.IGNORECASE,
)


def check_verdict_gates(parsed: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """
    Check the four gates. Returns (passed, failed).

    A gate passes when it carries a substantive answer. "N/A" or two words is a
    failure: the point of the gate is that the reasoning was actually done.
    """
    gates = parsed.get('verdict_gates') or {}
    passed, failed = [], []
    for name in VERDICT_GATES:
        answer = (gates.get(name) or '').strip()
        if len(answer) >= _GATE_MIN_CHARS and not _GATE_EMPTY.match(answer):
            passed.append(name)
        else:
            failed.append(name)
    return passed, failed


# ── Evidence grading ─────────────────────────────────────────────────────────

def grade_evidence(
    parsed: Dict[str, Any],
    evidence_results: List[Dict[str, Any]],
    tool_calls: Optional[List[str]],
    failed_gates: List[str],
) -> str:
    """
    verified   — deterministic queries executed successfully AND all gates passed
    partial    — some retrieval happened, but gates or citations are incomplete
    unverified — nothing was retrieved: the answer is the model talking to itself
    """
    successful_queries = [r for r in evidence_results if not r.get('error')]
    calls = [c for c in (tool_calls or []) if c]

    if not successful_queries and not calls:
        return 'unverified'
    if successful_queries and not failed_gates:
        return 'verified'
    return 'partial'


def apply_evidence_guard(parsed: Dict[str, Any], evidence_grade: str,
                         failed_gates: List[str]) -> Dict[str, Any]:
    """Downgrade an ungrounded verdict, and record why in guard_notes."""
    guarded = dict(parsed)
    notes: List[str] = []

    if evidence_grade == 'unverified':
        if guarded.get('verdict') and guarded['verdict'] != 'Undetermined':
            notes.append(
                f"Verdict downgraded from {guarded['verdict']} to Undetermined: "
                'no telemetry was retrieved for this incident.'
            )
        guarded['verdict'] = 'Undetermined'
        guarded['confidence'] = min(guarded.get('confidence') or 0, 39)
        guarded['suggested_determination'] = 'notEnoughData'
        guarded['proposed_actions'] = []
        notes.append('Automated response actions suppressed (no verified evidence).')

    elif evidence_grade == 'partial':
        cap = _int_config('TRIAGE_PARTIAL_CONFIDENCE_CAP', 69)
        if (guarded.get('confidence') or 0) > cap:
            notes.append(f'Confidence capped at {cap}: evidence coverage is partial.')
        guarded['confidence'] = min(guarded.get('confidence') or 0, cap)
        dropped = [a for a in guarded.get('proposed_actions') or []
                   if a['action_type'] in DESTRUCTIVE_ACTIONS]
        if dropped:
            notes.append(
                'Destructive action proposals suppressed on partial evidence: '
                + ', '.join(sorted({a['action_type'] for a in dropped}))
            )
        guarded['proposed_actions'] = [a for a in guarded.get('proposed_actions') or []
                                       if a['action_type'] not in DESTRUCTIVE_ACTIONS]

    if failed_gates:
        notes.append('Verdict gates not satisfied: ' + ', '.join(failed_gates))

    if not guarded.get('verdict'):
        guarded['verdict'] = 'Undetermined'
        notes.append('No parsable verdict in the agent response.')

    guarded['evidence_grade'] = evidence_grade
    guarded['failed_gates'] = failed_gates
    guarded['guard_notes'] = notes
    guarded['suggested_classification'] = VERDICT_TO_CLASSIFICATION.get(
        guarded['verdict'], 'unknown')
    return guarded


# ── Entity whitelist ─────────────────────────────────────────────────────────

def _incident_targets(incident: Dict[str, Any]) -> List[Dict[str, str]]:
    targets = []
    for entity in incident.get('entities') or []:
        etype = normalise_entity_type(entity.get('type'))
        name = (entity.get('name') or '').strip()
        if name:
            targets.append({'type': etype, 'value': name})
        for field in ('sha256', 'sha1'):
            if entity.get(field):
                targets.append({'type': 'file', 'value': str(entity[field]).strip()})
    return targets


def filter_actions_to_entities(
    actions: List[Dict[str, str]],
    incident: Dict[str, Any],
) -> Tuple[List[Dict[str, str]], List[str]]:
    """Keep only actions targeting a real incident entity of the right type."""
    targets = _incident_targets(incident)
    lookup = {t['value'].lower(): t['type'] for t in targets}
    kept: List[Dict[str, str]] = []
    notes: List[str] = []

    for action in actions:
        atype = action['action_type']
        value = (action.get('target_value') or '').strip()

        if atype == 'close_incident_fp':
            kept.append({**action, 'target_type': 'incident',
                         'target_value': str(incident.get('id'))})
            continue

        if not value:
            notes.append(f'{atype}: dropped — no target given')
            continue

        target_type = lookup.get(value.lower())
        if target_type is None:
            # Allow a device short name to resolve to its FQDN, nothing looser.
            short = value.lower().split('.')[0]
            match = next((t for t in targets
                          if t['value'].lower().split('.')[0] == short), None)
            if match:
                target_type, value = match['type'], match['value']
            else:
                notes.append(f'{atype}: dropped — "{value}" is not an entity on this incident')
                continue

        allowed = _ACTION_TARGET_TYPES.get(atype, ())
        if target_type not in allowed:
            notes.append(f'{atype}: dropped — target "{value}" is a {target_type}, '
                         f'expected {"/".join(allowed)}')
            continue

        kept.append({**action, 'target_type': target_type, 'target_value': value})

    return kept, notes


def _actions_allowed_by_policy(verdict: str, confidence: int) -> Tuple[bool, str]:
    floor = _int_config('TRIAGE_MIN_CONFIDENCE_FOR_ACTIONS', 70)
    if verdict == 'TruePositive' and confidence >= floor:
        return True, ''
    if verdict == 'FalsePositive' and confidence >= _int_config(
            'TRIAGE_AUTO_CLOSE_MIN_CONFIDENCE', 90):
        return True, ''
    return False, (f'Action proposals suppressed: {verdict} at {confidence}% confidence '
                   f'is below the policy floor ({floor}%).')


# ── Sentinel comment write-back ──────────────────────────────────────────────

def format_triage_comment(incident_id: str, result: Dict[str, Any]) -> str:
    """Build the incident comment within the Graph 1000-character limit."""
    lines = ['[SOC Dashboard - Autonomous Triage]',
             f"Verdict: {result.get('verdict')} | Confidence: {result.get('confidence')}% "
             f"| Evidence: {result.get('evidence_grade')}"]
    if result.get('model_tier'):
        lines.append(f"Model tier: {result['model_tier']} ({result.get('model') or 'unknown'})")

    queries = (result.get('evidence_queries_run') or 0)
    if queries:
        lines.append(f"Evidence queries run: {queries}")

    mitre = result.get('mitre') or {}
    if mitre.get('techniques'):
        lines.append(f"MITRE: {', '.join(mitre['techniques'][:6])}")

    header = '\n'.join(lines)
    footer_parts: List[str] = []

    if result.get('failed_gates'):
        footer_parts.append('Gates not met: ' + ', '.join(result['failed_gates']))
    actions = result.get('proposed_actions') or []
    if actions:
        footer_parts.append('Proposed containment (awaiting approval): '
                            + '; '.join(f"{a['action_type']} -> {a['target_value']}"
                                        for a in actions[:3]))
    if result.get('evidence_grade') == 'unverified':
        footer_parts.append('No telemetry retrieved - treat as untriaged.')

    footer = ('\n' + '\n'.join(footer_parts)) if footer_parts else ''
    budget = 1000 - len(header) - len(footer) - 4
    summary = defang((result.get('summary') or '').strip())
    if budget > 80 and summary:
        if len(summary) > budget:
            summary = summary[:budget].rsplit(' ', 1)[0] + '...'
        return f'{header}\n\n{summary}{footer}'[:1000]
    return f'{header}{footer}'[:1000]


# ── Orchestrator ─────────────────────────────────────────────────────────────

def triage_incident(
    incident_id: str,
    *,
    requested_by: str = 'autonomous_triage',
    user_token: Optional[str] = None,
    triage_token: Optional[str] = None,
    post_comment: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Run one autonomous triage pass.

    Returns {'success': bool, ...triage fields, 'actions': [...], 'error': str|None}.
    Response actions are recorded as proposals only.
    """
    incident = get_incident_by_id(incident_id)
    if not incident:
        return {'success': False, 'error': 'Incident not found in database'}

    routing = select_model_tier(incident)
    if not routing['deployment']:
        return {'success': False,
                'error': 'No Foundry deployment configured — set FOUNDRY_DEPLOYMENT in Settings'}

    # 1. Deterministic evidence.
    evidence_results: List[Dict[str, Any]] = []
    evidence_text = ''
    if _flag('TRIAGE_EVIDENCE_PACK_ENABLED', True):
        try:
            from triage_queries import format_evidence_for_prompt, run_evidence_pack
            evidence_results = run_evidence_pack(
                incident, days=_int_config('TRIAGE_BASELINE_DAYS', 7))
            evidence_text = format_evidence_for_prompt(evidence_results)
        except Exception:
            log.exception('⚠️  Evidence pack failed for %s', incident_id)
            evidence_text = 'Evidence collection failed — treat all evidence as unavailable.'

    alerts = get_incident_alerts(incident_id)
    prompt = build_triage_prompt(incident, alerts, evidence_text)

    # 2. Reasoning pass.
    try:
        from ai_assistant import ask_agent
        agent_result = ask_agent(
            prompt,
            user_token=user_token,
            triage_token=triage_token,
            deployment=routing['deployment'],
        )
    except Exception:
        log.exception('❌ Triage agent call failed for %s', incident_id)
        return {'success': False, 'error': 'Triage agent request failed'}

    answer = (agent_result or {}).get('answer') or ''
    if not answer:
        return {'success': False, 'error': 'Agent returned an empty response'}

    # 3. Parse, gate, grade, guard.
    tool_calls = (agent_result or {}).get('tool_calls') or []
    parsed = parse_triage_response(answer)
    passed_gates, failed_gates = check_verdict_gates(parsed)
    grade = grade_evidence(parsed, evidence_results, tool_calls, failed_gates)
    result = apply_evidence_guard(parsed, grade, failed_gates)

    # 4. Policy floor, then entity whitelist.
    verdict = result['verdict']
    confidence = int(result.get('confidence') or 0)
    allowed, policy_note = _actions_allowed_by_policy(verdict, confidence)
    if not allowed and result.get('proposed_actions'):
        result['guard_notes'].append(policy_note)
        result['proposed_actions'] = []

    kept, reject_notes = filter_actions_to_entities(
        result.get('proposed_actions') or [], incident)
    result['proposed_actions'] = kept
    result['guard_notes'].extend(reject_notes)

    # 5. Persist, including the full audit trail.
    trace = {
        'evidence_queries': [
            {'id': r['id'], 'name': r.get('name'), 'phase': r.get('phase'),
             'row_count': r['row_count'], 'error': r.get('error'), 'query': r['query']}
            for r in evidence_results
        ],
        'tool_calls': tool_calls,
        'kql': [agent_result.get('kql')] if agent_result.get('kql') else [],
        'evidence': parsed.get('evidence') or [],
        'verdict_gates': parsed.get('verdict_gates') or {},
        'gates_passed': passed_gates,
        'gates_failed': failed_gates,
        'guard_notes': result['guard_notes'],
        'ran_at': datetime.utcnow().isoformat() + 'Z',
        'requested_by': requested_by,
    }

    rca = dict(result.get('rca') or {})
    rca['capa'] = result.get('capa') or []

    triage_id = insert_triage(
        incident_id=str(incident_id),
        verdict=verdict,
        confidence=confidence,
        evidence_grade=grade,
        summary=result.get('summary'),
        risk_score=result.get('risk_score'),
        severity_assessment=result.get('severity_assessment'),
        suggested_classification=result.get('suggested_classification'),
        suggested_determination=result.get('suggested_determination'),
        mitre=result.get('mitre'),
        rca=rca,
        recommended_actions=result.get('recommended_actions'),
        entity_reputations=result.get('entity_reputations'),
        investigation_trace=trace,
        model=routing['deployment'],
        model_tier=routing['tier'],
        routing_reason=routing['reason'],
        raw_response=answer,
    )

    # 6. Record proposals. Never execute.
    recorded = []
    for action in result['proposed_actions']:
        if has_recent_action(incident_id, action['action_type'], action['target_value']):
            log.info('⏭️  Duplicate proposal skipped: %s -> %s',
                     action['action_type'], action['target_value'])
            continue
        action_id = create_response_action(
            incident_id=str(incident_id),
            action_type=action['action_type'],
            target_type=action.get('target_type'),
            target_value=action.get('target_value'),
            reason=action.get('reason'),
            triage_id=triage_id,
            requested_by=requested_by,
        )
        if action_id:
            recorded.append({**action, 'id': action_id, 'status': 'proposed'})

    result.update({
        'success': True,
        'error': None,
        'incident_id': str(incident_id),
        'triage_id': triage_id,
        'model': routing['deployment'],
        'model_tier': routing['tier'],
        'routing_reason': routing['reason'],
        'evidence_queries_run': len([r for r in evidence_results if not r.get('error')]),
        'evidence_queries_failed': len([r for r in evidence_results if r.get('error')]),
        'gates_passed': passed_gates,
        'actions': recorded,
        'tool_calls': tool_calls,
    })

    should_comment = (_flag('TRIAGE_AUTO_COMMENT_ENABLED', False)
                      if post_comment is None else post_comment)
    result['comment_posted'] = False
    if should_comment and str(incident_id).isdigit():
        try:
            from fetch_live_data import graph_post_comment
            graph_post_comment(str(incident_id), format_triage_comment(incident_id, result))
            result['comment_posted'] = True
            print(f'✅ Triage comment posted for incident {incident_id}')
        except Exception as exc:
            log.warning('⚠️  Triage comment post failed for %s: %s', incident_id, exc)

    print(f"🤖 Triage {incident_id}: {verdict} @ {confidence}% "
          f"(evidence={grade}, tier={routing['tier']}, "
          f"queries={result['evidence_queries_run']}, actions={len(recorded)})")
    return result


def auto_triage_incidents(incident_ids: List[str]) -> Dict[str, Any]:
    """
    Batch entry point for the ingest pipeline (append_data.py).

    Sequential on purpose: each pass runs several KQL queries plus a model call,
    and the workspace and deployment are the bottlenecks, not local concurrency.
    """
    if not _flag('TRIAGE_ENABLED', False):
        return {'triaged': 0, 'failed': 0, 'skipped': len(incident_ids),
                'reason': 'TRIAGE_ENABLED is off'}

    cap = max(1, min(50, _int_config('TRIAGE_MAX_PER_CYCLE', 10)))
    batch = [str(i) for i in incident_ids[:cap]]
    triaged = failed = 0

    for incident_id in batch:
        try:
            if triage_incident(incident_id, requested_by='ingest').get('success'):
                triaged += 1
            else:
                failed += 1
        except Exception as exc:
            log.warning('⚠️  Auto-triage failed for %s: %s', incident_id, exc)
            failed += 1

    skipped = len(incident_ids) - len(batch)
    print(f'🤖 Auto-triage: {triaged} triaged, {failed} failed, {skipped} skipped (cap: {cap})')
    return {'triaged': triaged, 'failed': failed, 'skipped': skipped}


# ── RCA export ───────────────────────────────────────────────────────────────

def format_rca_markdown(incident: Dict[str, Any], triage: Dict[str, Any]) -> str:
    """Render a stored triage record as an analyst-ready RCA document."""
    mitre = triage.get('mitre') or {}
    rca = triage.get('rca') or {}
    trace = triage.get('investigation_trace') or {}
    evidence = trace.get('evidence') or []
    gates = trace.get('verdict_gates') or {}

    def _block(items: List[str], empty: str) -> str:
        return '\n'.join(f'- {defang(i)}' for i in items) if items else f'- {empty}'

    kc_rows = '\n'.join(
        f"| {s.get('stage','')} | {s.get('technique','')} | {defang(s.get('observed',''))} |"
        for s in (rca.get('kill_chain') or [])
    ) or '| — | — | No kill chain established |'

    ev_lines = '\n'.join(
        f"- `[{e.get('source','unsourced')}]` {defang(e.get('finding',''))}" for e in evidence
    ) or '- No evidence recorded'

    gate_lines = '\n'.join(
        f"**{name.title()}** — {defang(gates.get(name)) or '_not answered_'}\n"
        for name in ('BASELINE', 'ALTERNATIVES', 'ATTRIBUTION', 'NEGATIVE FINDINGS')
    )

    queries = trace.get('evidence_queries') or []
    query_rows = '\n'.join(
        f"| {q.get('id')} | {q.get('row_count')} | {q.get('error') or 'ok'} |"
        for q in queries
    ) or '| — | — | no queries run |'

    failed_gates = trace.get('gates_failed') or []
    gate_warning = ('\n> ⚠️ Verdict gates not satisfied: '
                    + ', '.join(failed_gates) + '\n') if failed_gates else ''
    grade_warning = ('\n> ⚠️ Evidence grade is '
                     f"`{triage.get('evidence_grade')}` — this verdict is advisory only.\n"
                     if triage.get('evidence_grade') != 'verified' else '')

    return f"""# Incident RCA — {incident.get('title', 'Untitled')}

| | |
|---|---|
| **Incident** | {incident.get('id')} |
| **Verdict** | **{triage.get('verdict')}** ({triage.get('confidence')}% confidence) |
| **Evidence grade** | `{triage.get('evidence_grade')}` |
| **Assessed severity** | {triage.get('severity_assessment') or incident.get('severity')} |
| **Risk score** | {triage.get('risk_score') or 'n/a'}/100 |
| **Suggested classification** | {triage.get('suggested_classification')} / {triage.get('suggested_determination')} |
| **Model** | {triage.get('model')} ({triage.get('model_tier')} tier) — {triage.get('routing_reason')} |
| **Triaged at** | {triage.get('created_at')} |
{gate_warning}{grade_warning}
## 1. Executive summary

{defang(triage.get('summary')) or 'No summary recorded.'}

## 2. Evidence

{ev_lines}

## 3. Verdict gates

{gate_lines}

## 4. MITRE ATT&CK

- **Tactics:** {', '.join(mitre.get('tactics') or []) or 'None mapped'}
- **Techniques:** {', '.join(mitre.get('techniques') or []) or 'None mapped'}

## 5. Root cause

- **Patient zero:** {defang(rca.get('patient_zero')) or 'Not established'}
- **Initial access vector:** {defang(rca.get('initial_access_vector')) or 'Not established'}
- **Blast radius:** {defang(rca.get('blast_radius')) or 'Not established'}

| Stage | Technique | Observed |
|---|---|---|
{kc_rows}

## 6. Recommended actions

{_block(triage.get('recommended_actions') or [], 'None recorded')}

## 7. Corrective & preventive actions

{_block((rca.get('capa') or []), 'None recorded')}

## 8. Investigation audit trail

| Query | Rows | Status |
|---|---|---|
{query_rows}

- **Agent tools invoked:** {', '.join(trace.get('tool_calls') or []) or 'None'}
{_block(trace.get('guard_notes') or [], 'No guard adjustments applied')}

---
*Generated by SOC Dashboard autonomous triage. Indicators are defanged.
Verdicts are advisory; containment actions require analyst approval.*
"""
