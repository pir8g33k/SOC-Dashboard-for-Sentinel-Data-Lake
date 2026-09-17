# Autonomous Triage & Gated Response — Implementation Spec

Adds autonomous Tier-2 triage and analyst-approved incident response to
SOC-Dashboard-for-Sentinel-Data-Lake.

**Design position:** the agent decides, a human approves anything destructive.
Every automated verdict carries an evidence grade, and every containment action
is a proposal until an admin approves it. There is no code path in this package
that changes a production asset without an explicit approval call.

---

## 1. Pipeline

```
ingest (append_data.py)  ──or──  analyst clicks "Triage"
                │
                ▼
        select_model_tier()                 cheap vs reasoning deployment
                │
                ▼
        run_evidence_pack()                 10 version-controlled KQL queries
                │                           against Log Analytics (real rows)
                ▼
        ask_agent(contract prompt)          Foundry + Sentinel MCP; reasons over
                │                           retrieved rows, fills gaps with tools
                ▼
        parse_triage_response()             verdict, confidence, RCA, gates,
                │                           proposed ACTION: lines
                ▼
        check_verdict_gates()               baseline / alternatives /
                │                           attribution / negative findings
                ▼
        grade_evidence() ─► apply_evidence_guard()
                │                           verified | partial | unverified
                ▼
        policy floor ─► entity whitelist
                │
                ▼
        insert_triage() + create_response_action(status='proposed')
                │
                ▼
        [analyst reviews]  POST /api/response/actions/<id>/approve   (admin only)
                │
                ▼
        execute_response_action()           gates re-checked, atomic claim,
                                            target resolved, API called,
                                            true outcome written to audit trail
```

## 2. The five controls

| # | Control | Where | What it prevents |
|---|---|---|---|
| 1 | **Deterministic evidence pack** | `triage_queries.py` + `triage_queries/*.yaml` | Improvised KQL that queries non-existent tables, and unreproducible verdicts. Same incident → same queries, re-derivable months later. |
| 2 | **Verdict gates** | `check_verdict_gates()` | A verdict written without a baseline, without eliminating benign explanations, without attribution evidence, or without stating what was checked and found clean. |
| 3 | **Evidence guard** | `grade_evidence()` / `apply_evidence_guard()` | A confident verdict produced from failed queries. `unverified` forces `Undetermined`, caps confidence at 39 and suppresses all actions. |
| 4 | **Entity whitelist** | `filter_actions_to_entities()` | Acting on a hallucinated target. An action must name an entity present on the incident, of the right type for that action. |
| 5 | **Execution gates** | `response_actions.check_gates()` + dry run + atomic claim | Accidental or duplicated containment. Two flags, an admin route, dry-run-by-default, and a single-winner claim so a double-clicked approve cannot isolate a device twice. |

Zero rows is treated as a **confirmed negative finding**, not missing data.
A failed query is treated as **unavailable**, never as clean. That distinction is
the difference between triage and guesswork.

## 3. Configuration

All keys go through `config_manager` (encrypted DB → `.env` fallback). None are
secrets, so `SECRET_KEYS` is unchanged. Add them to `CONFIGURABLE_KEYS` and to
the `ALLOWED` set in `update_settings()` — see `PATCHES.md` §2c/§3.

### Triage

| Key | Default | Purpose |
|---|---|---|
| `TRIAGE_ENABLED` | `false` | Master switch for autonomous triage |
| `TRIAGE_AUTO_COMMENT_ENABLED` | `false` | Post the verdict as an incident comment |
| `TRIAGE_ROUTING_MODE` | `hybrid` | `hybrid` \| `always_fast` \| `always_deep` |
| `FOUNDRY_DEPLOYMENT_FAST` | falls back to `FOUNDRY_DEPLOYMENT` | Cheap tier |
| `FOUNDRY_DEPLOYMENT_DEEP` | falls back to `FOUNDRY_DEPLOYMENT` | Reasoning tier |
| `TRIAGE_MAX_PER_CYCLE` | `10` | Cap per ingest run |
| `TRIAGE_BASELINE_DAYS` | `7` | Recent window; baseline comparisons use 90d |
| `TRIAGE_EVIDENCE_PACK_ENABLED` | `true` | Run the deterministic queries |
| `TRIAGE_QUERY_DIR` | `./triage_queries` | Query pack location |
| `TRIAGE_MIN_CONFIDENCE_FOR_ACTIONS` | `70` | Floor for proposing any action |
| `TRIAGE_PARTIAL_CONFIDENCE_CAP` | `69` | Cap applied on partial evidence |
| `TRIAGE_AUTO_CLOSE_FP_ENABLED` | `false` | Allow automatic FP closure |
| `TRIAGE_AUTO_CLOSE_MIN_CONFIDENCE` | `90` | Floor for automatic FP closure |

### Response

| Key | Default | Purpose |
|---|---|---|
| `RESPONSE_ACTIONS_ENABLED` | `false` | Global kill switch |
| `RESPONSE_DRY_RUN` | **`true`** | Validate and log; record `simulated`, never execute |
| `RESPONSE_ALLOW_ISOLATE_DEVICE` | `false` | Permit MDE isolation |
| `RESPONSE_ALLOW_REVOKE_SESSIONS` | `false` | Permit session revocation |
| `RESPONSE_ALLOW_DISABLE_ACCOUNT` | `false` | Permit account disable |
| `RESPONSE_ALLOW_PUSH_IOC` | `false` | Permit TI indicator publishing |
| `RESPONSE_ALLOW_CLOSE_FP` | `false` | Permit FP closure |
| `RESPONSE_ISOLATION_TYPE` | `Full` | `Full` \| `Selective` |
| `RESPONSE_IOC_CONFIDENCE` | `75` | Confidence stamped on published indicators |
| `RESPONSE_FP_DETERMINATION` | `notMalicious` | Graph determination used on FP closure |

Both the global and per-action flags are re-checked **inside**
`execute_response_action()`, not only in the UI. Approval cannot bypass a
disabled action type.

## 4. Azure permissions

Existing app registration, four additions. The dashboard already holds
`SecurityIncident.ReadWrite.All` (comments, close) and Log Analytics read.

| Permission | API | Type | Needed for |
|---|---|---|---|
| `Machine.Read.All` | Defender for Endpoint | Application | Resolve a device name to an MDE machine id |
| `Machine.Isolate` | Defender for Endpoint | Application | Isolate device |
| `User.RevokeSessions.All` | Microsoft Graph | Application | Revoke sign-in sessions |
| `User.ReadWrite.All` | Microsoft Graph | Application | Disable account (also covers user lookup) |

`User.ReadWrite.All` is the sharpest of these — it permits directory writes well
beyond `accountEnabled`. If `RESPONSE_ALLOW_DISABLE_ACCOUNT` stays off, grant
`User.Read.All` + `User.RevokeSessions.All` instead and skip it entirely.

Publishing indicators uses the ARM token path already in `ioc_upload.py`
(`Microsoft Sentinel Contributor` on the workspace). No new grant.

New token scope in use: `https://api.securitycenter.microsoft.com/.default`,
obtained through the existing `get_graph_access_token(scope=...)` helper.

## 5. API surface

| Method | Route | Auth | Notes |
|---|---|---|---|
| POST | `/api/incidents/<id>/triage` | login | Runs triage; `{"force": true}` re-runs |
| GET | `/api/incidents/<id>/triage` | login | Latest stored verdict + actions |
| GET | `/api/incidents/<id>/triage/export` | login | Markdown RCA download |
| GET | `/api/incidents/<id>/actions` | login | Actions for one incident |
| GET | `/api/triage-stats?days=30` | login | Verdicts, evidence grades, action outcomes |
| GET | `/api/response/gates` | login | Which actions this deployment may perform |
| GET | `/api/response/actions?status=proposed` | login | Approval queue |
| POST | `/api/response/actions/<id>/approve` | **admin** | Executes (or simulates) |
| POST | `/api/response/actions/<id>/reject` | login | Declines, with a recorded reason |

`GET /api/response/gates` exists so the frontend can grey out what is disabled
rather than offering a button that will be refused.

## 6. Data model

**`incident_triage`** — one row per triage pass, newest wins. Verdict,
confidence, `evidence_grade`, Graph classification/determination suggestions,
MITRE, RCA (patient zero / kill chain / blast radius / CAPA),
`investigation_trace` (every query with its row count and status, tool calls,
gate answers, guard notes) and the raw response.

**`response_actions`** — one row per proposal. Statuses: `proposed` → `rejected`
\| `executing` → `executed` \| `failed` \| `simulated`. Carries requester,
approver, resolved target id, real API status code, `dry_run` and timestamps.

The trace is the point: it is what lets an analyst — or a customer's auditor —
see exactly which query produced which finding, and which gate the agent failed.

## 7. Rollout

**Stage 1 — shadow (week 1).** `TRIAGE_ENABLED=true`,
`TRIAGE_AUTO_COMMENT_ENABLED=false`, `RESPONSE_ACTIONS_ENABLED=false`.
Triage runs on ingest and writes to the DB only. Watch
`/api/triage-stats`: if `by_evidence_grade.unverified` is not near zero, the
query pack is failing against the workspace — fix that before anything else.

**Stage 2 — visible (week 2).** Enable `TRIAGE_AUTO_COMMENT_ENABLED`. Verdicts
appear on incidents. Spot-check ~20 against analyst judgement; compare the
verdict to the classification the analyst eventually sets.

**Stage 3 — dry-run response (week 3).** `RESPONSE_ACTIONS_ENABLED=true`,
`RESPONSE_DRY_RUN=true`, and turn on the specific `RESPONSE_ALLOW_*` flags you
want. Approving an action resolves the target, validates everything and records
`simulated` without calling the API. This is where target resolution gets
proven — wrong-device resolution surfaces here, not in production.

**Stage 4 — live, narrowest first.** `RESPONSE_DRY_RUN=false` with only
`RESPONSE_ALLOW_PUSH_IOC` and `RESPONSE_ALLOW_REVOKE_SESSIONS` on. Add
`RESPONSE_ALLOW_ISOLATE_DEVICE` once the queue has a track record.
`RESPONSE_ALLOW_DISABLE_ACCOUNT` and `TRIAGE_AUTO_CLOSE_FP_ENABLED` last, and
for a customer tenant only with written sign-off.

Reverting is a config change, not a deploy: set `RESPONSE_ACTIONS_ENABLED=false`
and all execution stops with proposals intact.

## 8. Provenance — what was adopted from where

Reviewed four repos. Ideas were taken; no implementation code was copied.

**`ankush351992/AI-SOC-Agent-for-Microsoft-Sentinel`**
- *Adopted:* the verdict + confidence + classification output shape; model-tier
  routing heuristics (severity → alert count → technique count); the structured
  RCA block (patient zero, kill chain, blast radius, CAPA); per-incident RCA
  export.
- *Rejected:* `remediation_service.py` (containment branches are `pass` yet
  report success and post "device isolated" to the real incident);
  `trigger_playbook()` (never calls the Logic App); the simulation fallbacks in
  `kql_runner`/`threat_intel` (fabricate rows and attributions on failure with
  `status: SUCCESS`); the keyword-matching "reasoning engine". Controls 3, 4 and
  5 above exist specifically to make those failure modes impossible here.

**`SCStelz/security-investigator`**
- *Adopted:* the four **verdict gates** (control 2) — the strongest idea in any
  of these repos; the **phased YAML query library** (control 1); the **IP
  prevalence test** as the empirical check on "shared infrastructure" (`E8`);
  **defanging** indicators in analyst-facing output.
- *Worth a separate look:* `mcp-apps/sentinel-incident-comment` ships a real
  Logic App (`infra/Sentinel-Incident-Add-Comment.json`) — a working example of
  the Sentinel-triggered playbook pattern; `automations/*.workflow.md` is a neat
  scheduling layer; `notes/memory/` gives an agent persistent tenant context.

**`davidalonsod/Dalonso-Security-Repo`**
- *Validated the design:* `EasyVistaITSM/.../EasyVista-TriggerResponseActions`
  is a deployable MDE response playbook with exactly this shape — token →
  resolve machine → switch on action type → execute → write the result back.
  It also has the ITSM write-back leg this package lacks (see §9).
- *Directly relevant elsewhere:* the AbuseIPDB **CCF connector** (definition,
  DCR, table, polling, 5 analytic rules, 7 hunting queries) is a strong template
  for the Cloudflare CCF work; `Sentinel Cost Optimization` is a ready-made
  ingestion-cost review pack; the ADFS rule set is 20 deployable analytic rules.

## 9. Known limitations

- **Device-side evidence is thin.** The query pack covers identity and IP
  comprehensively; device evidence relies on the agent's Defender MCP tools,
  because `DeviceProcessEvents` and friends live in Advanced Hunting, not this
  Log Analytics workspace. A phase-3 pack using `RunAdvancedHuntingQuery` via
  MCP is the natural next step.
- **No ITSM leg.** Actions are approved in the dashboard. Routing approvals
  through ServiceNow/EasyVista (as the Dalonso playbook does) would give a
  change record; the `response_actions` table is shaped to support it.
- **SQLite write contention.** Triage writes during the ingest run while
  gunicorn serves reads. The repo's own note applies: enable
  `PRAGMA journal_mode=WAL` if `database is locked` appears.
- **`str(exc)` in `response_actions.py`.** One deliberate occurrence: only
  `ActionError` messages, which are authored in-module to be analyst-safe.
  Provider response bodies are logged and replaced with a generic message by
  `_api_error()` before they can reach a client.
- **The agent can still be wrong.** These controls constrain *unfounded*
  confidence, not error. Every verdict stays advisory; the classification an
  analyst writes is the one of record.

## 10. Verification

`tests/test_triage.py` — 94 tests, hermetic (stubs `config_manager`, `database`,
`sentinel_kql`, `fetch_live_data`, `ioc_upload`; no credentials, no Azure, no
touching `soc_dashboard.db`).

```
python -m pytest tests/test_triage.py -v     # 94 passed
```

Coverage worth knowing about:

- Model routing across all six branches plus both override modes.
- Contract parsing, including malformed and truncated responses.
- Gate checking: substantive answers pass, `N/A` and two-word answers fail.
- Guard behaviour: `unverified` forces `Undetermined` and strips actions;
  `partial` caps confidence and strips only destructive actions.
- Zero rows grades as `verified`; failed queries grade as `unverified`.
- Entity whitelist: hallucinated host dropped, type mismatch dropped, short name
  resolves to FQDN, `close_incident_fp` always retargeted to the incident.
- KQL injection: five payloads rejected by `safe_value`/`safe_list`.
- Query pack assertions against the repo's own documented pitfalls — no
  non-existent tables, `tostring(AlertId)` before every join,
  `parse_json(Entities)` before every `mv-expand Entity`.
- Gating: nothing runs with flags off; dry run records `simulated`; a failing
  API records `failed`, never success; a second claim on the same action loses.
- Defanging, the 1000-character Graph comment budget, and RCA export warnings.
