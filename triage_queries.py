"""
Deterministic evidence collection for autonomous triage.

Instead of letting the model improvise KQL, triage runs a version-controlled
query pack against Log Analytics first, then hands the rows to the model to
reason over. Benefits over LLM-authored KQL:

  * Reproducible — the same incident produces the same queries, so a verdict
    can be re-derived months later for a customer or an auditor.
  * Reviewable — queries live in YAML under source control, not in a prompt.
  * Cheaper — no round trips spent discovering schemas.
  * Safe — entity values are validated against strict per-type patterns before
    substitution, so an entity name can never inject KQL.

Query pack layout (loaded from TRIAGE_QUERY_DIR, default ./triage_queries):
    triage_queries/phase1/E1-IncidentDetail.yaml
    triage_queries/phase2/E4-AccountSigninBaseline.yaml
    ...
"""

from __future__ import annotations

import glob
import logging
import os
import re
from typing import Any, Dict, Iterable, List, Optional

import yaml

from config_manager import get_config
from sentinel_kql import run_kql

log = logging.getLogger(__name__)

DEFAULT_QUERY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'triage_queries')

# Strict value patterns. A value that does not match is never substituted into a
# query — the query is skipped instead. This is the injection boundary.
_VALUE_PATTERNS = {
    'account': re.compile(r'^[A-Za-z0-9][A-Za-z0-9._\-]{0,62}(@[A-Za-z0-9][A-Za-z0-9.\-]{0,252})?$'),
    'device': re.compile(r'^[A-Za-z0-9][A-Za-z0-9._\-]{0,252}$'),
    'ip': re.compile(r'^[0-9a-fA-F:.]{3,45}$'),
    'file': re.compile(r'^[a-fA-F0-9]{32,64}$'),
    'url': re.compile(r'^[A-Za-z0-9._\-:/?=&%+~#@]{3,2048}$'),
    'incident': re.compile(r'^[A-Za-z0-9\-]{1,64}$'),
    'days': re.compile(r'^\d{1,3}$'),
}


class QuerySkipped(Exception):
    """A query could not be rendered safely and was skipped."""


def safe_value(kind: str, value: Any) -> str:
    """Validate a substitution value against its type pattern."""
    text = str(value).strip()
    pattern = _VALUE_PATTERNS.get(kind)
    if pattern is None:
        raise QuerySkipped(f'No validation pattern for value type "{kind}"')
    if not pattern.match(text):
        raise QuerySkipped(f'Value "{text[:60]}" is not a valid {kind}')
    return text


def safe_list(kind: str, values: Iterable[Any], limit: int = 20) -> str:
    """Render a validated dynamic([...]) list literal for KQL."""
    cleaned = []
    for value in values:
        try:
            cleaned.append(safe_value(kind, value))
        except QuerySkipped:
            continue
        if len(cleaned) >= limit:
            break
    if not cleaned:
        raise QuerySkipped(f'No valid {kind} values to query')
    inner = ', '.join(f'"{v}"' for v in cleaned)
    return f'dynamic([{inner}])'


# ── Pack loading ─────────────────────────────────────────────────────────────

def query_dir() -> str:
    return get_config('TRIAGE_QUERY_DIR') or DEFAULT_QUERY_DIR


def load_pack(directory: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load every query definition, sorted by phase then id."""
    directory = directory or query_dir()
    if not os.path.isdir(directory):
        log.warning('⚠️  Triage query directory not found: %s', directory)
        return []

    definitions: List[Dict[str, Any]] = []
    for path in sorted(glob.glob(os.path.join(directory, '**', '*.yaml'), recursive=True)):
        try:
            with open(path, 'r', encoding='utf-8') as handle:
                definition = yaml.safe_load(handle) or {}
        except Exception as exc:
            log.warning('⚠️  Could not parse query file %s: %s', path, exc)
            continue

        if not definition.get('id') or not definition.get('query'):
            log.warning('⚠️  Query file %s is missing id or query', path)
            continue
        definition['_path'] = path
        definition.setdefault('phase', 1)
        definition.setdefault('requires', [])
        definition.setdefault('name', definition['id'])
        definitions.append(definition)

    definitions.sort(key=lambda d: (int(d.get('phase') or 1), str(d.get('id'))))
    return definitions


# ── Rendering ────────────────────────────────────────────────────────────────

_PLACEHOLDER = re.compile(r'\{(?P<kind>account|device|ip|file|url|incident|days)'
                          r'(?P<plural>_list)?\}')


def render_query(definition: Dict[str, Any], context: Dict[str, Any]) -> str:
    """
    Substitute validated values into a query template.

    Placeholders: {account} {device} {ip} {file} {url} {incident} {days} for a
    single value, and {account_list} / {ip_list} / {file_list} for dynamic([...]).
    """
    query = str(definition['query'])

    def _replace(match: re.Match) -> str:
        kind = match.group('kind')
        if match.group('plural'):
            values = context.get(f'{kind}s') or []
            return safe_list(kind, values)
        value = context.get(kind)
        if value is None:
            raise QuerySkipped(f'No {kind} in context for {definition["id"]}')
        return safe_value(kind, value)

    return _PLACEHOLDER.sub(_replace, query)


def _requirements_met(definition: Dict[str, Any], context: Dict[str, Any]) -> bool:
    for requirement in definition.get('requires') or []:
        key = requirement if requirement.endswith('s') else requirement
        if not context.get(key) and not context.get(f'{requirement}s'):
            return False
    return True


# ── Execution ────────────────────────────────────────────────────────────────

def build_context(incident: Dict[str, Any], days: int = 7) -> Dict[str, Any]:
    """Derive the substitution context from an incident record."""
    from triage_agent import normalise_entity_type  # local import avoids a cycle

    accounts: List[str] = []
    devices: List[str] = []
    ips: List[str] = []
    files: List[str] = []
    urls: List[str] = []

    for entity in incident.get('entities') or []:
        etype = normalise_entity_type(entity.get('type'))
        name = (entity.get('name') or '').strip()
        bucket = {'account': accounts, 'device': devices,
                  'ip': ips, 'url': urls}.get(etype)
        if bucket is not None and name and name not in bucket:
            bucket.append(name)
        if etype == 'file':
            for field in ('sha256', 'sha1'):
                value = entity.get(field)
                if value and value not in files:
                    files.append(str(value))
            if name and re.match(r'^[a-fA-F0-9]{32,64}$', name) and name not in files:
                files.append(name)

    context: Dict[str, Any] = {
        'incident': str(incident.get('id') or ''),
        'days': str(int(days)),
        'accounts': accounts,
        'devices': devices,
        'ips': ips,
        'files': files,
        'urls': urls,
    }
    # Singular convenience values for single-entity queries.
    for key, values in (('account', accounts), ('device', devices),
                        ('ip', ips), ('file', files), ('url', urls)):
        if values:
            context[key] = values[0]
    return context


def run_evidence_pack(
    incident: Dict[str, Any],
    *,
    days: int = 7,
    max_phase: int = 2,
    row_cap: int = 30,
    workspace_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Run every applicable query for this incident.

    Returns one result dict per query:
      {id, name, description, phase, query, row_count, rows, error}

    A failed query is reported with its error and does not abort the pack — the
    verdict then reflects partial evidence rather than pretending completeness.
    """
    context = build_context(incident, days=days)
    results: List[Dict[str, Any]] = []

    for definition in load_pack():
        if int(definition.get('phase') or 1) > max_phase:
            continue
        if not _requirements_met(definition, context):
            continue

        try:
            query = render_query(definition, context)
        except QuerySkipped as exc:
            log.info('⏭️  Query %s skipped: %s', definition['id'], exc)
            continue

        entry: Dict[str, Any] = {
            'id': definition['id'],
            'name': definition.get('name'),
            'description': definition.get('description'),
            'phase': definition.get('phase'),
            'query': query,
            'row_count': 0,
            'rows': [],
            'error': None,
        }
        try:
            rows = run_kql(query, workspace_id=workspace_id)
            entry['row_count'] = len(rows)
            entry['rows'] = rows[:row_cap]
        except Exception as exc:
            log.warning('⚠️  Evidence query %s failed: %s', definition['id'], exc)
            entry['error'] = 'query failed'
        results.append(entry)

    return results


def format_evidence_for_prompt(results: List[Dict[str, Any]], char_budget: int = 12000) -> str:
    """Render pack results as compact text for the model, within a budget."""
    if not results:
        return 'No deterministic evidence queries were run.'

    blocks: List[str] = []
    used = 0
    for entry in results:
        header = f"### {entry['id']} — {entry['name']}"
        if entry.get('error'):
            body = f"QUERY FAILED ({entry['error']}). Treat this evidence as unavailable."
        elif entry['row_count'] == 0:
            body = 'No rows returned. This is a confirmed negative finding.'
        else:
            lines = [f"{entry['row_count']} row(s):"]
            for row in entry['rows']:
                compact = ', '.join(f'{k}={v}' for k, v in row.items() if v not in (None, ''))
                lines.append(f'  - {compact[:400]}')
            body = '\n'.join(lines)

        block = f'{header}\n{body}\n'
        if used + len(block) > char_budget:
            blocks.append('(evidence truncated — remaining queries omitted for length)')
            break
        blocks.append(block)
        used += len(block)

    return '\n'.join(blocks)


def evidence_sources(results: List[Dict[str, Any]]) -> List[str]:
    """Query ids that actually returned rows — the citable sources."""
    return [r['id'] for r in results if not r.get('error') and r['row_count'] > 0]
