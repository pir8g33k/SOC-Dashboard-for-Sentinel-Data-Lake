# File Inventory — SOC Dashboard

> Last updated: 2026-09-18

## Source Files

| File | Purpose | Key Dependencies |
|------|---------|-----------------|
| `dashboard_backend.py` | Flask API server. Serves dashboard data, auth routes, settings API. Protected by Entra ID login. Includes CSP + security headers. | flask, flask-cors, flask-session, database.py, fetch_live_data.py, auth.py, config_manager.py |
| `database.py` | SQLite schema definition, table creation, CRUD helpers for incidents/alerts/entities/threat-intel/metrics/config. Parameterised queries throughout. | sqlite3 (stdlib) |
| `fetch_live_data.py` | Data fetchers: Microsoft Graph Security API (incidents, Secure Score, MDTI), Sentinel KQL (Log Analytics REST API), VirusTotal, AbuseIPDB, Talos. Two-tier fallback: Graph → Sentinel (returns empty when no credentials). Includes `graph_post_comment()` for posting enrichment results as incident comments (max 1000 chars). | requests, msal, python-dotenv, config_manager.py |
| `append_data.py` | Incremental data loader — fetches new incidents/alerts and inserts only those not already in DB. | database.py, fetch_live_data.py |
| `hourly_refresh.py` | Long-running scheduler with configurable interval from DB settings. Includes 5-min timeout per fetch cycle. | schedule, concurrent.futures, append_data.py, config_manager.py |
| `auth.py` | Entra ID OAuth2 authorization code flow (multi-tenant). Login, callback, logout, `@require_login` and `@require_admin` decorators. | msal, flask |
| `config_manager.py` | Encrypted configuration CRUD. DB→env fallback for all settings. Fernet encryption for secrets. | cryptography, database.py |
| `ioc_upload.py` | IOC upload engine — uploads threat intelligence indicators to Sentinel via REST API. Supports single IOC, bulk CSV, and open-source feed ingestion with deduplication. Auto-discovers workspace/resource-group via Resource Graph. | requests, config_manager.py, database.py |
| `ai_assistant.py` | Azure AI Foundry integration — agent mode with Sentinel MCP tools (data-exploration + triage), direct completion fallback. Caches attack stories. | openai, azure-identity, config_manager.py |
| `security_copilot.py` | Security Copilot enrichment module — prompt construction, response parsing, on-demand enrichment via Foundry agent, Logic App webhook processing, auto-enrich batch helper. Results cached 1 hour. Enrichment posted as Sentinel comment (≤1000 chars). | ai_assistant.py, database.py, config_manager.py |
| `sentinel_kql.py` | KQL query engine — runs ad-hoc KQL queries against Log Analytics REST API with safety limits (row cap, timeout). | requests, config_manager.py |
| `triage_agent.py` | Autonomous triage orchestrator — model-tier routing, structured verdict contract, response parsing, four verdict gates, evidence grading and guard downgrades, entity whitelisting, incident comment write-back, Markdown RCA rendering. Records containment as proposals only. | config_manager.py, triage_db.py, triage_queries.py, ai_assistant.py, fetch_live_data.py |
| `triage_queries.py` | Evidence pack loader and runner — reads the YAML query pack, validates entity values against strict per-type patterns before substitution (the KQL injection boundary), executes via `sentinel_kql.run_kql`, formats results for the prompt. | pyyaml, sentinel_kql.py, config_manager.py |
| `triage_db.py` | `incident_triage` and `response_actions` schema with an idempotent migration, plus CRUD: triage insert/read/batch/stats, action create/claim/finish/reject, duplicate-proposal guard. Atomic single-winner claim on approval. | sqlite3 (stdlib), database.py |
| `response_actions.py` | Gated containment executors — MDE device isolation, Entra session revocation, account disable, Sentinel TI indicator push, false-positive closure. Resolves targets against MDE and Entra (ambiguous match fails rather than guesses), enforces global + per-action flags at execution time, honours `RESPONSE_DRY_RUN`, writes the true outcome to the incident audit trail. | requests, config_manager.py, triage_db.py, fetch_live_data.py, ioc_upload.py, database.py |
| `routes_triage.py` | Flask blueprint for triage and response actions — run/get/export triage, action queue, gate state, triage stats, admin-only approve, reject. | flask, auth.py, triage_db.py, triage_agent.py, response_actions.py |
| `soc-dashboard-live.html` | Single-page frontend — KPI cards, charts (Chart.js), incident table, timeline filters, IOC upload tab, light/dark theme toggle. Auth-gated with Entra ID login redirect. Admin settings overlay. | Chart.js 4.4 (CDN) |
| `setup.html` | First-run setup wizard. Presented when Entra ID credentials are missing/placeholder. Saves config to encrypted DB via `/api/setup`. Self-disables after setup completes. | — (standalone HTML) |

## Triage Evidence Queries (`triage_queries/`)

Version-controlled KQL run before the model reasons, so a verdict can be re-derived
later. Placeholders (`{account_list}`, `{ip_list}`, `{incident}`, `{days}`) are
substituted only after the value passes its type pattern.

| File | Phase | Purpose |
|------|-------|---------|
| `phase1/E1-IncidentDetail.yaml` | 1 | Authoritative `SecurityIncident` row — current status and classification |
| `phase1/E2-IncidentAlerts.yaml` | 1 | Correlated alerts with tactics/techniques, for alert-cohesion checking |
| `phase1/E3-AlertEntities.yaml` | 1 | Entity inventory straight from alert evidence |
| `phase2/E4-AccountSigninBaseline.yaml` | 2 | Sign-in volume, success/failure split, IPs, countries, apps per account |
| `phase2/E5-AccountNewSourceIPs.yaml` | 2 | Source IPs absent from the prior 90-day baseline (leftanti join) |
| `phase2/E6-AccountRiskEvents.yaml` | 2 | Entra ID Protection risk detections |
| `phase2/E7-AccountDirectoryActivity.yaml` | 2 | `AuditLogs` operations where the account is actor or target |
| `phase2/E8-IPPrevalence.yaml` | 2 | Tenant-wide prevalence per source IP — the empirical shared-infrastructure test |
| `phase2/E9-IPThreatIntel.yaml` | 2 | Active `ThreatIntelligenceIndicator` matches for the incident's IPs |
| `phase2/E10-RelatedIncidents.yaml` | 2 | Other incidents touching the same accounts in 30 days |

## Tests (`tests/`)

| File | Purpose |
|------|---------|
| `tests/test_triage.py` | 94 hermetic tests for triage and response. Stubs `config_manager`, `database`, `sentinel_kql`, `fetch_live_data` and `ioc_upload`, so it runs without Azure credentials and never touches `soc_dashboard.db`. Covers model routing, contract parsing, verdict gates, guard downgrades, entity whitelisting, KQL injection rejection, query-pack conformance to the workspace's documented table/join pitfalls, execution gating, defanging and the 1000-char comment budget. |

## Scripts (`scripts/`)

| File | Purpose |
|------|---------|
| `scripts/pre_commit_check.py` | Pre-commit scanner for leaked secrets and common vulns |
| `scripts/generate_demo_data.py` | Standalone demo data generator. Writes `dashboard_data.json` with synthetic incidents, alerts, Secure Score. Optional `--db` flag inserts into SQLite. |
| `scripts/deploy_lxc.sh` | Automated FHS-compliant deployment to Ubuntu 24.04 LXC. Auto-generates self-signed TLS if no Let's Encrypt cert. Merges new `.env.example` keys into existing `.env`. Auto-detects `server_name` from `REDIRECT_URI`. Includes health checks. |
| `scripts/reset_test_lxc.sh` | Full test LXC reset — stops services, wipes DB/sessions/config key, resets `.env` to placeholders, clears journal+file logs, pulls latest code, starts dashboard in setup-wizard mode. One-command clean slate for test cycles. |
| `scripts/update_from_git.sh` | Git-based update/install script. Clones on first run, pulls on subsequent runs. Auto-restarts services, updates pip deps if requirements.txt changed. Supports `--branch`, `--no-restart`, `--full-deploy` flags. |
| `scripts/setup_systemd.sh` | Creates systemd units: dashboard.service + hourly-refresh.timer (FHS paths) |
| `scripts/nginx_site.conf` | nginx reverse proxy config template (replace `YOUR_DOMAIN` before use) |

> Retired scripts (one-off migrations, debug helpers, Windows-only launchers) are in `_archive/` (gitignored).

## Configuration

| File | Purpose |
|------|---------|
| `.env.example` | Template for required environment variables (safe to commit) |
| `.gitignore` | Security-hardened ignore rules — blocks `.env`, `*.db`, `*.key`, `*secret*` |
| `requirements.txt` | Pinned Python dependencies |

## Documentation

| File | Purpose |
|------|---------|
| `README.md` | Quick start, feature summary, project structure, production deployment guide |
| `docs/ARCHITECTURE.md` | Component diagram, data flow, DB schema, tech stack, deployment topology |
| `docs/INVENTORY.md` | This file — file-by-file inventory |
| `docs/AI_SETUP.md` | How to configure Azure AI Foundry / OpenAI integration (agent mode, direct completion, MCP tools) |
| `docs/AUTONOMOUS_TRIAGE.md` | Autonomous triage + gated response — pipeline, the five safety controls, config reference, Azure permission matrix, API surface, data model, staged rollout, known limitations |
| `docs/SECURITY_FIXES.md` | Tracked vulnerability discoveries and patches (14 entries) |
| `SECURITY.md` | GitHub security policy (vulnerability reporting) |
| `LICENSE` | MIT License |

## Static Assets

| File | Purpose |
|------|---------|
| `static/favicon.svg` | Shield favicon (SVG, served via Flask route) |
| `static/chart.umd.min.js` | Chart.js 4.4 local bundle (CDN fallback) |

## Copilot / Agent Files

| File | Purpose |
|------|---------|
| `.github/copilot-instructions.md` | Coding conventions, security rules, pitfalls for Copilot agents |
| `skills/soc-dashboard-deployment/SKILL.md` | Copilot skill: LXC deployment, systemd, nginx, TLS, DNS, known pitfalls |

## Runtime Artifacts (gitignored)

| File | Created By | Purpose |
|------|-----------|---------|
| `.env` | User | Real credentials |
| `soc_dashboard.db` | `database.py` | SQLite database |
| `dashboard_data.json` | `fetch_live_data.py` | JSON fallback data |
| `*.log` | Various | Log output |

## External API Dependencies

| API | Used By | Auth Method | Required Permission |
|-----|---------|-------------|-------------------|
| Microsoft Graph `/security/incidents` | fetch_live_data.py | OAuth2 client_credentials | SecurityIncident.Read.All |
| Microsoft Graph `/security/incidents/{id}/comments` | fetch_live_data.py | OAuth2 client_credentials | SecurityIncident.ReadWrite.All |
| Microsoft Graph `/security/secureScores` | fetch_live_data.py | OAuth2 client_credentials | SecurityEvents.Read.All |
| Microsoft Graph `/security/threatIntelligence/articles` | fetch_live_data.py | OAuth2 client_credentials | ThreatIntelligence.Read.All |
| Microsoft Sentinel (Log Analytics REST API) | fetch_live_data.py | OAuth2 client_credentials | Log Analytics Reader |
| Microsoft Defender XDR (incidents/alerts) | fetch_live_data.py | OAuth2 (Graph fallback) | SecurityIncident.Read.All |
| Microsoft Sentinel (Threat Intelligence) | ioc_upload.py | OAuth2 client_credentials | Microsoft.Sentinel (Contributor or TI Contributor) |
| Azure Resource Graph | ioc_upload.py | OAuth2 client_credentials | Reader |
| Azure AI Foundry (OpenAI) | ai_assistant.py | Entra SP (client_credentials) | Cognitive Services OpenAI User |
| Microsoft Graph `/users/{id}/revokeSignInSessions` | response_actions.py | OAuth2 client_credentials | User.RevokeSessions.All *(optional)* |
| Microsoft Graph `PATCH /users/{id}` (`accountEnabled`) | response_actions.py | OAuth2 client_credentials | User.ReadWrite.All *(optional)* |
| Defender for Endpoint `/api/machines` | response_actions.py | OAuth2 client_credentials | Machine.Read.All *(optional)* |
| Defender for Endpoint `/api/machines/{id}/isolate` | response_actions.py | OAuth2 client_credentials | Machine.Isolate *(optional)* |
| Microsoft Sentinel (Log Analytics REST API) | triage_queries.py | OAuth2 client_credentials | Log Analytics Reader |
| VirusTotal `/api/v3/files` | fetch_live_data.py | API key header | VirusTotal API key |
| Microsoft Sentinel TI (ARM REST API) | ioc_upload.py | OAuth2 client_credentials | Microsoft Sentinel Contributor |
| AbuseIPDB | fetch_live_data.py | Derived from incidents | — |
| Cisco Talos | fetch_live_data.py | Derived from incidents | — |
