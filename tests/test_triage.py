"""
Tests for autonomous triage and gated response.

Hermetic: the repo's config_manager / database / sentinel_kql are replaced with
in-memory stubs before import, so these run without Azure credentials, without
a Foundry deployment and without touching the real soc_dashboard.db.

    python -m pytest tests/test_triage.py -v
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import types

import pytest

# ── Stub the repo modules the units under test import ────────────────────────

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

CONFIG: dict = {}
_DB_PATH = os.path.join(tempfile.mkdtemp(prefix='triage-test-'), 'test.db')


def _fake_get_config(key, default=None):
    value = CONFIG.get(key)
    return default if value is None else value


config_manager = types.ModuleType('config_manager')
config_manager.get_config = _fake_get_config
config_manager.set_config = lambda key, value: CONFIG.__setitem__(key, value)
sys.modules['config_manager'] = config_manager


def _fake_get_connection():
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


database = types.ModuleType('database')
database.get_connection = _fake_get_connection
database.update_incident_field = lambda incident_id, column, value: True
sys.modules['database'] = database

KQL_CALLS: list = []
KQL_RESULT: list = []
KQL_RAISES = {'value': False}


def _fake_run_kql(query, workspace_id=None):
    KQL_CALLS.append(query)
    if KQL_RAISES['value']:
        raise RuntimeError('KQL query failed (401)')
    return list(KQL_RESULT)


sentinel_kql = types.ModuleType('sentinel_kql')
sentinel_kql.run_kql = _fake_run_kql
sys.modules['sentinel_kql'] = sentinel_kql

fetch_live_data = types.ModuleType('fetch_live_data')
fetch_live_data.get_graph_access_token = lambda scope=None: 'fake-token'
fetch_live_data.graph_post_comment = lambda incident_id, text: {'id': 'c1'}
fetch_live_data.graph_patch_incident = lambda incident_id, payload: {'id': incident_id}
sys.modules['fetch_live_data'] = fetch_live_data

ioc_upload = types.ModuleType('ioc_upload')
ioc_upload.validate_ioc = lambda ioc_type, value: (True, '')
ioc_upload.upload_single_ioc = lambda **kwargs: {'name': 'ind-1'}
sys.modules['ioc_upload'] = ioc_upload

# ── Now import the units under test ─────────────────────────────────────────

import response_actions  # noqa: E402
import triage_agent  # noqa: E402
import triage_db  # noqa: E402
import triage_queries  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_state():
    """Reset config and database between tests."""
    CONFIG.clear()
    KQL_CALLS.clear()
    KQL_RESULT.clear()
    KQL_RAISES['value'] = False

    conn = _fake_get_connection()
    conn.executescript('''
        DROP TABLE IF EXISTS incidents;
        DROP TABLE IF EXISTS alerts;
        DROP TABLE IF EXISTS incident_triage;
        DROP TABLE IF EXISTS response_actions;
        CREATE TABLE incidents (id TEXT PRIMARY KEY, data JSON NOT NULL);
        CREATE TABLE alerts (id TEXT PRIMARY KEY, incident_id TEXT,
                             timestamp TEXT, data JSON NOT NULL);
    ''')
    conn.commit()
    conn.close()
    triage_db.init_triage_schema()
    yield


# ── Fixtures ────────────────────────────────────────────────────────────────

INCIDENT = {
    'id': '81192',
    'title': 'Suspicious sign-in followed by mailbox rule creation',
    'severity': 'High',
    'status': 'Active',
    'createdTime': '2026-09-17T02:00:00Z',
    'alertCount': 3,
    'mitreTechniques': ['T1078', 'T1114.003'],
    'entities': [
        {'type': 'userAccount', 'name': 'alice@contoso.com', 'verdict': 'suspicious'},
        {'type': 'device', 'name': 'HK-LT-042.contoso.com', 'verdict': 'unknown'},
        {'type': 'ip', 'name': '203.0.113.9', 'verdict': 'malicious'},
        {'type': 'file', 'name': 'dropper.exe',
         'sha256': 'a' * 64, 'verdict': 'malicious'},
    ],
}

GOOD_ANSWER = """\
## VERDICT
TruePositive

## CONFIDENCE
88

## DETERMINATION
compromisedAccount

## RISK SCORE
82

## SEVERITY ASSESSMENT
High

## EXECUTIVE SUMMARY
An adversary authenticated as alice@contoso.com from a source IP that has never
appeared in the account's 90-day baseline, then created an inbox forwarding rule.

## EVIDENCE
- [E4-AccountSigninBaseline] 312 sign-ins, 289 failures, single source IP
- [E5-AccountNewSourceIPs] 203.0.113.9 absent from the 90-day baseline
- [E8-IPPrevalence] DistinctAccounts = 1, so shared egress is eliminated

## VERDICT GATES
BASELINE: Compared the 7-day window against the prior 90 days of SigninLogs; the
  account had only ever signed in from two Hong Kong IPs before this event.
ALTERNATIVES: Corporate VPN egress considered and eliminated by E8 (one account
  only). Admin-performed rule creation considered and eliminated by E7, which
  shows the rule was created by the user principal, not an administrator.
ATTRIBUTION: The forwarding rule creation in E7 shares the session id with the
  anomalous sign-in in E4, tying the persistence step to the same session.
NEGATIVE FINDINGS: E9 returned zero rows, so the IP has no threat-intelligence
  match in this tenant. E6 shows no Identity Protection detections.

## MITRE
Tactics: Initial Access, Persistence, Collection
Techniques: T1078, T1114.003

## ROOT CAUSE
Patient zero: alice@contoso.com
Initial access vector: Credential replay from an unseen source IP
Kill chain:
Initial Access | T1078 | Sign-in from 203.0.113.9, absent from baseline
Persistence | T1114.003 | Inbox forwarding rule created in the same session
Blast radius: One identity, one mailbox; no device compromise confirmed

## RECOMMENDED ACTIONS
1. Revoke sessions for alice@contoso.com
2. Remove the forwarding rule
3. Force password reset with MFA re-registration

## CAPA
1. Require phishing-resistant MFA for this group
2. Alert on inbox forwarding rule creation

## ENTITY REPUTATIONS
- alice@contoso.com (account): compromised, confirmed persistence
- 203.0.113.9 (ip): singleton source, no TI match in tenant

## PROPOSED ACTIONS
ACTION: revoke_sessions | target: alice@contoso.com | reason: confirmed session compromise
ACTION: push_ioc | target: 203.0.113.9 | reason: sole source of the compromise
ACTION: isolate_device | target: NOT-A-REAL-HOST | reason: hallucinated target
ACTION: nuke_tenant | target: contoso.com | reason: unsupported action type
"""


# ── Model routing ───────────────────────────────────────────────────────────

class TestModelRouting:
    def setup_method(self):
        CONFIG.update({'FOUNDRY_DEPLOYMENT': 'base',
                       'FOUNDRY_DEPLOYMENT_FAST': 'mini',
                       'FOUNDRY_DEPLOYMENT_DEEP': 'reasoning'})

    def test_low_severity_uses_fast_tier(self):
        result = triage_agent.select_model_tier({'severity': 'Low', 'alertCount': 1})
        assert result['tier'] == 'fast'
        assert result['deployment'] == 'mini'

    def test_high_severity_uses_deep_tier(self):
        result = triage_agent.select_model_tier({'severity': 'High', 'alertCount': 1})
        assert result['tier'] == 'deep'
        assert result['deployment'] == 'reasoning'

    def test_medium_with_multiple_alerts_escalates(self):
        result = triage_agent.select_model_tier({'severity': 'Medium', 'alertCount': 3})
        assert result['tier'] == 'deep'

    def test_medium_with_multiple_techniques_escalates(self):
        result = triage_agent.select_model_tier(
            {'severity': 'Medium', 'alertCount': 1, 'mitreTechniques': ['T1078', 'T1114']})
        assert result['tier'] == 'deep'

    def test_medium_single_alert_stays_fast(self):
        result = triage_agent.select_model_tier(
            {'severity': 'Medium', 'alertCount': 1, 'mitreTechniques': ['T1078']})
        assert result['tier'] == 'fast'

    def test_routing_mode_overrides(self):
        CONFIG['TRIAGE_ROUTING_MODE'] = 'always_fast'
        assert triage_agent.select_model_tier({'severity': 'High'})['tier'] == 'fast'
        CONFIG['TRIAGE_ROUTING_MODE'] = 'always_deep'
        assert triage_agent.select_model_tier({'severity': 'Low'})['tier'] == 'deep'

    def test_falls_back_to_single_deployment(self):
        CONFIG.pop('FOUNDRY_DEPLOYMENT_FAST')
        CONFIG.pop('FOUNDRY_DEPLOYMENT_DEEP')
        assert triage_agent.select_model_tier({'severity': 'High'})['deployment'] == 'base'


# ── Parsing ─────────────────────────────────────────────────────────────────

class TestParsing:
    def test_parses_core_fields(self):
        parsed = triage_agent.parse_triage_response(GOOD_ANSWER)
        assert parsed['verdict'] == 'TruePositive'
        assert parsed['confidence'] == 88
        assert parsed['suggested_determination'] == 'compromisedAccount'
        assert parsed['risk_score'] == 82
        assert parsed['severity_assessment'] == 'High'
        assert 'forwarding rule' in parsed['summary']

    def test_parses_sourced_evidence(self):
        parsed = triage_agent.parse_triage_response(GOOD_ANSWER)
        sources = {e['source'] for e in parsed['evidence']}
        assert 'E4-AccountSigninBaseline' in sources
        assert 'E8-IPPrevalence' in sources
        assert all(e['finding'] for e in parsed['evidence'])

    def test_parses_all_four_gates(self):
        parsed = triage_agent.parse_triage_response(GOOD_ANSWER)
        assert set(parsed['verdict_gates']) == set(triage_agent.VERDICT_GATES)
        assert 'prior 90 days' in parsed['verdict_gates']['BASELINE']

    def test_parses_mitre_and_kill_chain(self):
        parsed = triage_agent.parse_triage_response(GOOD_ANSWER)
        assert parsed['mitre']['techniques'] == ['T1078', 'T1114.003']
        assert len(parsed['rca']['kill_chain']) == 2
        assert parsed['rca']['kill_chain'][0]['stage'] == 'Initial Access'
        assert parsed['rca']['patient_zero'] == 'alice@contoso.com'

    def test_drops_unsupported_action_type(self):
        parsed = triage_agent.parse_triage_response(GOOD_ANSWER)
        types_seen = {a['action_type'] for a in parsed['proposed_actions']}
        assert 'nuke_tenant' not in types_seen
        assert types_seen == {'revoke_sessions', 'push_ioc', 'isolate_device'}

    def test_invalid_determination_falls_back_to_unknown(self):
        answer = GOOD_ANSWER.replace('compromisedAccount', 'totallyPwned')
        assert triage_agent.parse_triage_response(answer)['suggested_determination'] == 'unknown'

    def test_action_none_produces_no_actions(self):
        answer = GOOD_ANSWER.split('## PROPOSED ACTIONS')[0] + \
            '## PROPOSED ACTIONS\nACTION: none\n'
        assert triage_agent.parse_triage_response(answer)['proposed_actions'] == []

    def test_missing_sections_do_not_raise(self):
        parsed = triage_agent.parse_triage_response('## VERDICT\nFalsePositive\n')
        assert parsed['verdict'] == 'FalsePositive'
        assert parsed['confidence'] is None
        assert parsed['proposed_actions'] == []
        assert parsed['verdict_gates'] == {}


# ── Verdict gates ───────────────────────────────────────────────────────────

class TestVerdictGates:
    def test_substantive_answers_pass(self):
        parsed = triage_agent.parse_triage_response(GOOD_ANSWER)
        passed, failed = triage_agent.check_verdict_gates(parsed)
        assert failed == []
        assert len(passed) == 4

    def test_na_answer_fails(self):
        parsed = {'verdict_gates': {'BASELINE': 'N/A', 'ALTERNATIVES': 'none',
                                    'ATTRIBUTION': '-', 'NEGATIVE FINDINGS': 'TBD'}}
        passed, failed = triage_agent.check_verdict_gates(parsed)
        assert passed == []
        assert len(failed) == 4

    def test_too_short_answer_fails(self):
        parsed = {'verdict_gates': {'BASELINE': 'looked at logs'}}
        _, failed = triage_agent.check_verdict_gates(parsed)
        assert 'BASELINE' in failed

    def test_missing_block_fails_all(self):
        _, failed = triage_agent.check_verdict_gates({})
        assert set(failed) == set(triage_agent.VERDICT_GATES)


# ── Evidence grading and guard ──────────────────────────────────────────────

class TestEvidenceGuard:
    def test_no_retrieval_is_unverified(self):
        grade = triage_agent.grade_evidence({}, [], [], [])
        assert grade == 'unverified'

    def test_successful_queries_and_gates_is_verified(self):
        results = [{'id': 'E4', 'row_count': 3, 'error': None}]
        assert triage_agent.grade_evidence({}, results, [], []) == 'verified'

    def test_zero_rows_still_counts_as_evidence(self):
        """A confirmed negative finding is evidence, not an absence of it."""
        results = [{'id': 'E9', 'row_count': 0, 'error': None}]
        assert triage_agent.grade_evidence({}, results, [], []) == 'verified'

    def test_failed_queries_only_is_unverified(self):
        results = [{'id': 'E4', 'row_count': 0, 'error': 'query failed'}]
        assert triage_agent.grade_evidence({}, results, [], []) == 'unverified'

    def test_failed_gates_downgrade_to_partial(self):
        results = [{'id': 'E4', 'row_count': 3, 'error': None}]
        assert triage_agent.grade_evidence({}, results, [], ['BASELINE']) == 'partial'

    def test_unverified_forces_undetermined_and_strips_actions(self):
        parsed = triage_agent.parse_triage_response(GOOD_ANSWER)
        guarded = triage_agent.apply_evidence_guard(parsed, 'unverified', [])
        assert guarded['verdict'] == 'Undetermined'
        assert guarded['confidence'] <= 39
        assert guarded['suggested_determination'] == 'notEnoughData'
        assert guarded['proposed_actions'] == []
        assert guarded['suggested_classification'] == 'unknown'
        assert any('downgraded' in note for note in guarded['guard_notes'])

    def test_partial_caps_confidence_and_strips_destructive_actions(self):
        parsed = triage_agent.parse_triage_response(GOOD_ANSWER)
        guarded = triage_agent.apply_evidence_guard(parsed, 'partial', ['BASELINE'])
        assert guarded['confidence'] == 69
        types_seen = {a['action_type'] for a in guarded['proposed_actions']}
        assert 'revoke_sessions' not in types_seen   # destructive
        assert 'isolate_device' not in types_seen    # destructive
        assert 'push_ioc' in types_seen              # non-destructive survives

    def test_verified_preserves_verdict(self):
        parsed = triage_agent.parse_triage_response(GOOD_ANSWER)
        guarded = triage_agent.apply_evidence_guard(parsed, 'verified', [])
        assert guarded['verdict'] == 'TruePositive'
        assert guarded['confidence'] == 88
        assert guarded['suggested_classification'] == 'truePositive'

    def test_missing_verdict_becomes_undetermined(self):
        guarded = triage_agent.apply_evidence_guard({'confidence': 90}, 'verified', [])
        assert guarded['verdict'] == 'Undetermined'


# ── Entity whitelist ────────────────────────────────────────────────────────

class TestEntityWhitelist:
    def test_hallucinated_target_is_dropped(self):
        actions = [{'action_type': 'isolate_device', 'target_value': 'NOT-A-REAL-HOST',
                    'reason': 'x'}]
        kept, notes = triage_agent.filter_actions_to_entities(actions, INCIDENT)
        assert kept == []
        assert any('not an entity' in n for n in notes)

    def test_real_entity_is_kept_with_type(self):
        actions = [{'action_type': 'revoke_sessions',
                    'target_value': 'alice@contoso.com', 'reason': 'x'}]
        kept, _ = triage_agent.filter_actions_to_entities(actions, INCIDENT)
        assert len(kept) == 1
        assert kept[0]['target_type'] == 'account'

    def test_type_mismatch_is_dropped(self):
        """An IP cannot be isolated, even though the IP is a real entity."""
        actions = [{'action_type': 'isolate_device', 'target_value': '203.0.113.9',
                    'reason': 'x'}]
        kept, notes = triage_agent.filter_actions_to_entities(actions, INCIDENT)
        assert kept == []
        assert any('expected device' in n for n in notes)

    def test_device_short_name_resolves_to_fqdn(self):
        """A model naming the NetBIOS short name still resolves to the real FQDN."""
        kept, _ = triage_agent.filter_actions_to_entities(
            [{'action_type': 'isolate_device', 'target_value': 'HK-LT-042'}], INCIDENT)
        assert len(kept) == 1
        assert kept[0]['target_value'] == 'HK-LT-042.contoso.com'
        assert kept[0]['target_type'] == 'device'

    def test_similar_but_different_host_does_not_resolve(self):
        kept, notes = triage_agent.filter_actions_to_entities(
            [{'action_type': 'isolate_device', 'target_value': 'HK-LT-999'}], INCIDENT)
        assert kept == []
        assert any('not an entity' in n for n in notes)

    def test_file_hash_target_is_allowed_for_ioc(self):
        kept, _ = triage_agent.filter_actions_to_entities(
            [{'action_type': 'push_ioc', 'target_value': 'a' * 64}], INCIDENT)
        assert len(kept) == 1
        assert kept[0]['target_type'] == 'file'

    def test_close_fp_always_targets_the_incident(self):
        kept, _ = triage_agent.filter_actions_to_entities(
            [{'action_type': 'close_incident_fp', 'target_value': 'whatever'}], INCIDENT)
        assert kept[0]['target_value'] == '81192'
        assert kept[0]['target_type'] == 'incident'


class TestActionPolicy:
    def test_true_positive_above_floor_allowed(self):
        allowed, _ = triage_agent._actions_allowed_by_policy('TruePositive', 85)
        assert allowed

    def test_true_positive_below_floor_blocked(self):
        allowed, note = triage_agent._actions_allowed_by_policy('TruePositive', 55)
        assert not allowed
        assert 'policy floor' in note

    def test_undetermined_never_allowed(self):
        assert not triage_agent._actions_allowed_by_policy('Undetermined', 99)[0]

    def test_false_positive_needs_high_confidence(self):
        assert not triage_agent._actions_allowed_by_policy('FalsePositive', 80)[0]
        assert triage_agent._actions_allowed_by_policy('FalsePositive', 95)[0]


# ── Query pack safety ───────────────────────────────────────────────────────

class TestQuerySafety:
    def test_valid_values_accepted(self):
        assert triage_queries.safe_value('account', 'alice@contoso.com') == 'alice@contoso.com'
        assert triage_queries.safe_value('ip', '203.0.113.9') == '203.0.113.9'
        assert triage_queries.safe_value('file', 'a' * 64) == 'a' * 64
        assert triage_queries.safe_value('days', '7') == '7'

    @pytest.mark.parametrize('payload', [
        "alice@contoso.com' | project 1 //",
        'x") or true or ("',
        'alice@contoso.com\n| union SecurityAlert',
        '*',
        '',
    ])
    def test_injection_payloads_rejected(self, payload):
        with pytest.raises(triage_queries.QuerySkipped):
            triage_queries.safe_value('account', payload)

    def test_safe_list_skips_bad_values_and_keeps_good(self):
        rendered = triage_queries.safe_list(
            'ip', ['203.0.113.9', "1.1.1.1' //", '198.51.100.7'])
        assert rendered == 'dynamic(["203.0.113.9", "198.51.100.7"])'

    def test_safe_list_raises_when_nothing_valid(self):
        with pytest.raises(triage_queries.QuerySkipped):
            triage_queries.safe_list('ip', ["' or 1==1 //"])

    def test_render_substitutes_single_and_list(self):
        definition = {'id': 'T1',
                      'query': 'SigninLogs | where UserPrincipalName in~ ({account_list}) '
                               '| where TimeGenerated > ago({days}d)'}
        context = {'accounts': ['alice@contoso.com'], 'days': '7'}
        rendered = triage_queries.render_query(definition, context)
        assert 'dynamic(["alice@contoso.com"])' in rendered
        assert 'ago(7d)' in rendered

    def test_render_skips_when_context_missing(self):
        with pytest.raises(triage_queries.QuerySkipped):
            triage_queries.render_query({'id': 'T2', 'query': 'X | where Y == "{device}"'}, {})

    def test_build_context_buckets_entities(self):
        context = triage_queries.build_context(INCIDENT, days=7)
        assert context['accounts'] == ['alice@contoso.com']
        assert context['devices'] == ['HK-LT-042.contoso.com']
        assert context['ips'] == ['203.0.113.9']
        assert 'a' * 64 in context['files']
        assert context['incident'] == '81192'
        assert context['days'] == '7'


class TestQueryPack:
    def test_shipped_pack_loads_and_renders(self):
        pack = triage_queries.load_pack()
        assert len(pack) >= 10, 'expected the shipped query pack to load'
        assert {d['id'] for d in pack} >= {'E1-IncidentDetail', 'E8-IPPrevalence'}
        context = triage_queries.build_context(INCIDENT, days=7)
        rendered = 0
        for definition in pack:
            try:
                query = triage_queries.render_query(definition, context)
            except triage_queries.QuerySkipped:
                continue
            rendered += 1
            # No unsubstituted placeholder of a known kind may survive rendering.
            assert not any(f'{{{kind}}}' in query for kind in
                           ('account', 'device', 'ip', 'file', 'url', 'incident', 'days'))
            assert not any(f'{{{kind}_list}}' in query for kind in
                           ('account', 'ip', 'file'))
        assert rendered >= 8

    def test_pack_only_uses_tables_present_in_this_workspace(self):
        """Guards the documented pitfall: these tables do not exist here."""
        forbidden = ('SecurityEvent', 'CommonSecurityLog', 'Syslog',
                     'OfficeActivity', 'AADRiskySignIns', 'Heartbeat')
        for definition in triage_queries.load_pack():
            for table in forbidden:
                assert table not in definition['query'], \
                    f"{definition['id']} references non-existent table {table}"

    def test_pack_casts_alertid_before_join(self):
        """mv-expand AlertId stays dynamic; the tostring cast is mandatory."""
        for definition in triage_queries.load_pack():
            query = definition['query']
            if 'mv-expand AlertId' in query:
                assert 'extend AlertId = tostring(AlertId)' in query, \
                    f"{definition['id']} expands AlertIds without casting to string"

    def test_pack_parses_entities_json_string(self):
        for definition in triage_queries.load_pack():
            query = definition['query']
            if 'mv-expand Entity' in query:
                assert 'parse_json(Entities)' in query, \
                    f"{definition['id']} must parse_json(Entities) before mv-expand"

    def test_run_evidence_pack_records_failures_without_raising(self):
        KQL_RAISES['value'] = True
        results = triage_queries.run_evidence_pack(INCIDENT)
        assert results, 'expected queries to be attempted'
        assert all(r['error'] == 'query failed' for r in results)
        assert triage_queries.evidence_sources(results) == []

    def test_run_evidence_pack_returns_rows(self):
        KQL_RESULT.extend([{'UserPrincipalName': 'alice@contoso.com', 'SignIns': 312}])
        results = triage_queries.run_evidence_pack(INCIDENT)
        assert any(r['row_count'] == 1 for r in results)
        text = triage_queries.format_evidence_for_prompt(results)
        assert 'SignIns=312' in text

    def test_zero_rows_is_labelled_a_negative_finding(self):
        results = triage_queries.run_evidence_pack(INCIDENT)
        text = triage_queries.format_evidence_for_prompt(results)
        assert 'confirmed negative finding' in text.lower()


# ── Persistence ─────────────────────────────────────────────────────────────

class TestPersistence:
    def test_migration_is_idempotent(self):
        triage_db.init_triage_schema()
        triage_db.init_triage_schema()
        conn = _fake_get_connection()
        tables = {r['name'] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()
        assert {'incident_triage', 'response_actions'} <= tables

    def test_triage_round_trip_hydrates_json(self):
        triage_id = triage_db.insert_triage(
            incident_id='81192', verdict='TruePositive', confidence=88,
            evidence_grade='verified', summary='Compromised account',
            mitre={'tactics': ['Initial Access'], 'techniques': ['T1078']},
            rca={'patient_zero': 'alice@contoso.com', 'capa': ['Enforce MFA']},
            recommended_actions=['Revoke sessions'],
            investigation_trace={'tool_calls': ['query_lake'], 'gates_failed': []},
            model='reasoning', model_tier='deep', routing_reason='High severity')
        assert triage_id

        stored = triage_db.get_triage('81192')
        assert stored['verdict'] == 'TruePositive'
        assert stored['mitre']['techniques'] == ['T1078']
        assert stored['rca']['capa'] == ['Enforce MFA']
        assert stored['investigation_trace']['tool_calls'] == ['query_lake']

    def test_latest_triage_wins(self):
        triage_db.insert_triage('81192', 'Undetermined', 20, 'unverified', 'first')
        triage_db.insert_triage('81192', 'TruePositive', 90, 'verified', 'second')
        assert triage_db.get_triage('81192')['summary'] == 'second'

    def test_actions_are_created_as_proposals(self):
        action_id = triage_db.create_response_action(
            '81192', 'isolate_device', 'device', 'HK-LT-0042.contoso.com', 'confirmed')
        action = triage_db.get_response_action(action_id)
        assert action['status'] == 'proposed'
        assert action['dry_run'] == 0
        assert action['executed_at'] is None

    def test_unknown_action_type_is_refused(self):
        assert triage_db.create_response_action('81192', 'nuke_tenant', None, 'x', 'y') is None

    def test_claim_is_single_winner(self):
        """A double-clicked approve button must not isolate a device twice."""
        action_id = triage_db.create_response_action(
            '81192', 'isolate_device', 'device', 'HK-LT-0042.contoso.com', 'r')
        assert triage_db.claim_response_action(action_id, 'james') is True
        assert triage_db.claim_response_action(action_id, 'james') is False

    def test_finish_records_outcome(self):
        action_id = triage_db.create_response_action(
            '81192', 'revoke_sessions', 'account', 'alice@contoso.com', 'r')
        triage_db.claim_response_action(action_id, 'james')
        triage_db.finish_response_action(action_id, 'executed', 'Sessions revoked',
                                        api_status_code=200, resolved_target_id='obj-1')
        action = triage_db.get_response_action(action_id)
        assert action['status'] == 'executed'
        assert action['api_status_code'] == 200
        assert action['resolved_target_id'] == 'obj-1'

    def test_reject_only_from_proposed(self):
        action_id = triage_db.create_response_action(
            '81192', 'disable_account', 'account', 'alice@contoso.com', 'r')
        assert triage_db.reject_response_action(action_id, 'james', 'not needed') is True
        assert triage_db.reject_response_action(action_id, 'james', 'again') is False

    def test_duplicate_proposal_detection(self):
        triage_db.create_response_action(
            '81192', 'isolate_device', 'device', 'HK-LT-0042.contoso.com', 'r')
        assert triage_db.has_recent_action('81192', 'isolate_device',
                                           'HK-LT-0042.contoso.com') is True
        assert triage_db.has_recent_action('81192', 'isolate_device', 'OTHER-HOST') is False

    def test_rejected_action_does_not_block_reproposal(self):
        action_id = triage_db.create_response_action(
            '81192', 'isolate_device', 'device', 'HK-LT-0042.contoso.com', 'r')
        triage_db.reject_response_action(action_id, 'james')
        assert triage_db.has_recent_action('81192', 'isolate_device',
                                           'HK-LT-0042.contoso.com') is False

    def test_stats_report_verdicts_and_grades(self):
        triage_db.insert_triage('1', 'TruePositive', 90, 'verified', 's')
        triage_db.insert_triage('2', 'FalsePositive', 95, 'verified', 's')
        triage_db.insert_triage('3', 'Undetermined', 20, 'unverified', 's')
        stats = triage_db.get_triage_stats(30)
        assert stats['incidents_triaged'] == 3
        assert stats['by_verdict']['TruePositive'] == 1
        assert stats['by_evidence_grade']['unverified'] == 1


# ── Response gating ─────────────────────────────────────────────────────────

class TestResponseGating:
    def test_everything_off_by_default(self):
        for action_type in response_actions.ACTION_FLAGS:
            allowed, reason = response_actions.check_gates(action_type)
            assert not allowed
            assert 'RESPONSE_ACTIONS_ENABLED' in reason or 'not permitted' in reason

    def test_global_flag_alone_is_not_enough(self):
        CONFIG['RESPONSE_ACTIONS_ENABLED'] = 'true'
        allowed, reason = response_actions.check_gates('isolate_device')
        assert not allowed
        assert 'RESPONSE_ALLOW_ISOLATE_DEVICE' in reason

    def test_both_flags_required(self):
        CONFIG.update({'RESPONSE_ACTIONS_ENABLED': 'true',
                       'RESPONSE_ALLOW_ISOLATE_DEVICE': 'true'})
        assert response_actions.check_gates('isolate_device')[0] is True
        assert response_actions.check_gates('disable_account')[0] is False

    def test_dry_run_defaults_on(self):
        assert response_actions._dry_run() is True
        CONFIG['RESPONSE_DRY_RUN'] = 'false'
        assert response_actions._dry_run() is False

    def test_unknown_action_type_refused(self):
        CONFIG.update({'RESPONSE_ACTIONS_ENABLED': 'true'})
        assert response_actions.check_gates('rm_rf')[0] is False

    def test_execute_refuses_when_gated(self):
        action_id = triage_db.create_response_action(
            '81192', 'isolate_device', 'device', 'HK-LT-0042.contoso.com', 'r')
        result = response_actions.execute_response_action(action_id, 'james')
        assert result['success'] is False
        assert triage_db.get_response_action(action_id)['status'] == 'proposed'

    def test_execute_refuses_non_proposed_action(self):
        CONFIG.update({'RESPONSE_ACTIONS_ENABLED': 'true',
                       'RESPONSE_ALLOW_PUSH_IOC': 'true'})
        action_id = triage_db.create_response_action(
            '81192', 'push_ioc', 'ip', '203.0.113.9', 'r')
        triage_db.claim_response_action(action_id, 'someone')
        result = response_actions.execute_response_action(action_id, 'james')
        assert result['success'] is False
        assert 'already' in result['message']

    def test_dry_run_records_simulated_not_executed(self):
        CONFIG.update({'RESPONSE_ACTIONS_ENABLED': 'true',
                       'RESPONSE_ALLOW_PUSH_IOC': 'true',
                       'RESPONSE_DRY_RUN': 'true'})
        action_id = triage_db.create_response_action(
            '81192', 'push_ioc', 'ip', '203.0.113.9', 'sole source')
        result = response_actions.execute_response_action(action_id, 'james')
        assert result['success'] is True
        assert result['status'] == 'simulated'
        assert 'DRY RUN' in result['message']
        assert triage_db.get_response_action(action_id)['dry_run'] == 1

    def test_live_run_records_executed(self):
        CONFIG.update({'RESPONSE_ACTIONS_ENABLED': 'true',
                       'RESPONSE_ALLOW_PUSH_IOC': 'true',
                       'RESPONSE_DRY_RUN': 'false'})
        action_id = triage_db.create_response_action(
            '81192', 'push_ioc', 'ip', '203.0.113.9', 'sole source')
        result = response_actions.execute_response_action(action_id, 'james')
        assert result['status'] == 'executed'
        stored = triage_db.get_response_action(action_id)
        assert stored['status'] == 'executed'
        assert stored['dry_run'] == 0
        assert stored['executed_at'] is not None

    def test_failure_is_recorded_as_failed_not_success(self):
        """The bug this design exists to avoid: reporting success for nothing."""
        CONFIG.update({'RESPONSE_ACTIONS_ENABLED': 'true',
                       'RESPONSE_ALLOW_PUSH_IOC': 'true',
                       'RESPONSE_DRY_RUN': 'false'})

        def _boom(**kwargs):
            raise RuntimeError('Sentinel API error: HTTP 403')

        ioc_upload.upload_single_ioc = _boom
        try:
            action_id = triage_db.create_response_action(
                '81192', 'push_ioc', 'ip', '203.0.113.9', 'r')
            result = response_actions.execute_response_action(action_id, 'james')
            assert result['success'] is False
            assert result['status'] == 'failed'
            assert triage_db.get_response_action(action_id)['status'] == 'failed'
        finally:
            ioc_upload.upload_single_ioc = lambda **kwargs: {'name': 'ind-1'}

    def test_describe_gates_shape(self):
        gates = response_actions.describe_gates()
        assert gates['dry_run'] is True
        assert gates['response_actions_enabled'] is False
        assert gates['actions']['isolate_device']['destructive'] is True
        assert gates['actions']['push_ioc']['destructive'] is False


class TestIocClassification:
    def test_hash_lengths_map_to_stix_types(self):
        assert response_actions.classify_ioc('file', 'a' * 32) == 'file:md5'
        assert response_actions.classify_ioc('file', 'a' * 40) == 'file:sha1'
        assert response_actions.classify_ioc('file', 'a' * 64) == 'file:sha256'

    def test_ip_versions(self):
        assert response_actions.classify_ioc('ip', '203.0.113.9') == 'ipv4-addr'
        assert response_actions.classify_ioc('ip', '2001:db8::1') == 'ipv6-addr'

    def test_url_versus_domain(self):
        assert response_actions.classify_ioc('url', 'https://evil.example/x') == 'url'
        assert response_actions.classify_ioc('url', 'evil.example') == 'domain-name'

    def test_bad_hash_raises(self):
        with pytest.raises(response_actions.ActionError):
            response_actions.classify_ioc('file', 'not-a-hash')

    def test_unsupported_entity_type_raises(self):
        with pytest.raises(response_actions.ActionError):
            response_actions.classify_ioc('device', 'HK-LT-0042')


# ── Output hygiene ──────────────────────────────────────────────────────────

class TestDefang:
    def test_public_ip_is_defanged(self):
        assert triage_agent.defang('seen from 203.0.113.9') == 'seen from 203[.]0[.]113[.]9'

    def test_private_ip_is_left_readable(self):
        assert '192.168.1.10' in triage_agent.defang('internal 192.168.1.10')

    def test_url_scheme_is_broken(self):
        assert 'hxxps://' in triage_agent.defang('https://evil.top/payload')

    def test_domain_is_defanged(self):
        assert 'evil[.]top' in triage_agent.defang('contacted evil.top')

    def test_none_is_safe(self):
        assert triage_agent.defang(None) == ''


class TestCommentFormatting:
    def test_comment_fits_graph_limit(self):
        result = {'verdict': 'TruePositive', 'confidence': 88, 'evidence_grade': 'verified',
                  'model_tier': 'deep', 'model': 'reasoning',
                  'evidence_queries_run': 9,
                  'summary': 'x' * 4000,
                  'mitre': {'techniques': ['T1078']},
                  'proposed_actions': [{'action_type': 'revoke_sessions',
                                        'target_value': 'alice@contoso.com'}]}
        comment = triage_agent.format_triage_comment('81192', result)
        assert len(comment) <= 1000
        assert 'Verdict: TruePositive' in comment
        assert 'awaiting approval' in comment

    def test_unverified_comment_warns(self):
        result = {'verdict': 'Undetermined', 'confidence': 20,
                  'evidence_grade': 'unverified', 'summary': 'nothing retrieved'}
        comment = triage_agent.format_triage_comment('81192', result)
        assert 'treat as untriaged' in comment

    def test_failed_gates_appear_in_comment(self):
        result = {'verdict': 'TruePositive', 'confidence': 69, 'evidence_grade': 'partial',
                  'failed_gates': ['BASELINE'], 'summary': 'partial'}
        comment = triage_agent.format_triage_comment('81192', result)
        assert 'Gates not met: BASELINE' in comment


# ── RCA export ──────────────────────────────────────────────────────────────

class TestRcaExport:
    def test_export_contains_gates_and_audit_trail(self):
        triage_db.insert_triage(
            incident_id='81192', verdict='TruePositive', confidence=88,
            evidence_grade='verified', summary='Compromise of alice@contoso.com from 203.0.113.9',
            mitre={'tactics': ['Initial Access'], 'techniques': ['T1078']},
            rca={'patient_zero': 'alice@contoso.com',
                 'kill_chain': [{'stage': 'Initial Access', 'technique': 'T1078',
                                 'observed': 'sign-in from 203.0.113.9'}],
                 'capa': ['Enforce phishing-resistant MFA']},
            recommended_actions=['Revoke sessions'],
            investigation_trace={
                'evidence_queries': [{'id': 'E4-AccountSigninBaseline', 'row_count': 1,
                                      'error': None}],
                'tool_calls': ['query_lake'],
                'verdict_gates': {'BASELINE': 'Compared 7d against prior 90d of SigninLogs'},
                'gates_failed': [], 'guard_notes': []},
            model='reasoning', model_tier='deep', routing_reason='High severity')

        markdown = triage_agent.format_rca_markdown(
            INCIDENT, triage_db.get_triage('81192'))
        assert 'Verdict Gates'.lower() in markdown.lower()
        assert 'E4-AccountSigninBaseline' in markdown
        assert 'query_lake' in markdown
        assert '203[.]0[.]113[.]9' in markdown, 'indicators must be defanged in exports'
        assert '203.0.113.9' not in markdown

    def test_unverified_export_carries_a_warning(self):
        triage_db.insert_triage('81192', 'Undetermined', 20, 'unverified', 'nothing',
                                investigation_trace={'gates_failed': ['BASELINE']})
        markdown = triage_agent.format_rca_markdown(
            INCIDENT, triage_db.get_triage('81192'))
        assert 'advisory only' in markdown
        assert 'gates not satisfied' in markdown.lower()
