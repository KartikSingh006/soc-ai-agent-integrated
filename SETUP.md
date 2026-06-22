# SOC AI Agent — Setup & What Changed

This document covers what was added/changed in this pass, how to run the
system, and the security steps you must take before using this anywhere
past localhost.

## ⚠️ Do this first

1. **Rotate the VirusTotal API key** that was in your originally uploaded
   `_env` file (`d6f8f50...`). It was exposed in this chat session and
   must be treated as compromised. Generate a new one at
   https://www.virustotal.com/gui/my-apikey and put it in your own
   `.env` (see below) — never in `.env.example` or committed to git.
2. Copy `.env.example` to `.env` in the project root and fill in real
   values for `SECRET_KEY`, `INTERNAL_SERVICE_TOKEN`, `ADMIN_PASSWORD`,
   and `DJANGO_WEBHOOK_SECRET` at minimum. Random strings are fine:
   `openssl rand -hex 32`.
3. After first login, change the default admin password immediately
   (`PATCH` isn't exposed for self-password-change yet — easiest is
   `POST /auth/users` to create your real account, then `DELETE
   /auth/users/admin` to deactivate the bootstrap one).

## What was added in this pass

### 1. Postgres persistence (100%)
- **TIP Platform** previously kept IOC intel in an in-memory dict — lost
  on every restart. Now backed by the `ioc_intel` table via
  `IOCRepository`, with the same VirusTotal → local-intel → heuristic
  fallback chain as before.
- **Response Engine** previously only logged to an in-memory list.
  `/execute`, `/playbook/execute`, and `/revert` now persist every
  action to the `response_actions` table, including who requested it.
- **Alembic migrations** (`migrations/`) didn't exist at all before —
  tables had been created by hand. There's now a real `0001_initial`
  migration covering all 10 tables, and every service runs
  `wait_for_postgres()` + `alembic upgrade head` (under a Postgres
  advisory lock, so 4 services starting simultaneously don't race) on
  startup, gated by `RUN_MIGRATIONS_ON_STARTUP=true`.

### 2. Real LLM analysis (already mostly present — hardened)
The AI Orchestrator already called real Anthropic/OpenAI APIs with a
heuristic fallback when no key is configured. This pass fixed:
- LLM responses wrapped in ` ```json ` fences were breaking `json.loads`
  silently and falling back to heuristics every time — now stripped.
- The default Claude model name was stale — now `claude-sonnet-4-6`.

### 3. RBAC / Auth (new)
JWT-based, three roles: `admin`, `analyst`, `viewer`. Login lives on the
SIEM Engine (`POST /auth/login`); the resulting JWT is valid against
*all four services* since they share `SECRET_KEY`. Service-to-service
calls (siem → orchestrator → tip/response) use a separate
`INTERNAL_SERVICE_TOKEN` header (`X-Internal-Token`) so a leaked user
token can never be replayed as a service identity.

- `viewer`: read-only on everything.
- `analyst`: + create/update alerts, assets, approve/reject response
  actions, run playbooks.
- `admin`: + user management, audit log access.

A bootstrap admin user (`ADMIN_USERNAME`/`ADMIN_PASSWORD`, defaults
`admin` / `change-me-now`) is created once on first startup if the
`users` table is empty.

### 4. Audit logging (new)
Every mutation — login attempts, alert status changes, asset upserts,
incident creation, response-action approve/reject, user management,
Django ticket sync — writes a row to `audit_log` in the same
transaction as the change itself. View via `GET /audit-log` on the AI
Orchestrator (admin-only).

### 5. Human-approval gate (new)
The `DecisionAgent` already computed a `contain_with_approval` decision
for medium-confidence threats, but nothing previously *did* anything
with it. Now:
- `contain_with_approval` → recommended actions are persisted as
  `response_actions` rows with `status="pending_approval"` — nothing is
  executed.
- `auto_contain` (high confidence + high risk score) still executes
  immediately, unchanged.
- New endpoints on the AI Orchestrator:
  - `GET /response-actions/pending` (analyst/admin)
  - `POST /response-actions/{id}/approve` (analyst/admin) — calls
    Response Engine's `/execute`, records the result, updates the
    linked incident.
  - `POST /response-actions/{id}/reject` (analyst/admin)
- The dashboard's "Pending Approvals" panel gives analysts a one-click
  UI for this instead of needing curl/Postman.

### 6. Django Ticket Management System sync (new)
Optional — controlled by `DJANGO_BASE_URL`. When unset, incidents are
created normally and `django_ticket_id`/`django_ticket_status` just
stay `null` (same fallback pattern as VirusTotal/CrowdStrike already
used in this codebase).
- On incident creation, `DjangoTicketClient.create_ticket()` POSTs to
  `{DJANGO_BASE_URL}{DJANGO_TICKET_ENDPOINT}`.
- `POST /webhooks/django-ticket-update` receives status changes back
  from Django (validated against `DJANGO_WEBHOOK_SECRET`) and reflects
  them onto the incident (e.g. Django "closed" → incident "resolved").
- `POST /incidents/{id}/sync-ticket` lets an analyst manually retry a
  sync that failed (e.g. Django was down).
- **You'll need to adjust `DjangoTicketClient`'s field names** in
  `shared/integrations.py` to match your actual Django ticket app's API
  contract — it's written against a generic
  `{title, description, severity, source, source_id, metadata}` shape.

### 7. Live CrowdStrike integration (already present — bug fixed)
The OAuth2 client-credentials flow and real Falcon API calls
(`contain_host`, `lift_containment`, `get_host_details`) already
existed. The bug: Falcon containment actions need the device's **agent
ID (AID)**, not its hostname, but `isolate_host`/`restore_host` were
passing hostname directly. Added `resolve_aid_by_hostname()` and
`contain_host_by_hostname()`/`lift_containment_by_hostname()` wrappers
that do the lookup first. Falls back to simulated mode exactly as
before when `CROWDSTRIKE_CLIENT_ID`/`SECRET` aren't configured.

### 8. Dashboard (rebuilt)
Was a static placeholder with no live API calls. Now a working
single-page app (`dashboard/index.html`, vanilla JS, no build step):
login screen, live service-health pipeline, recent alerts/incidents,
and the pending-approvals panel with approve/reject buttons. JWT is
kept in `localStorage` — that's fine here since this is your own
deployed app, not a sandboxed environment.

## Running it

```bash
cp .env.example .env
# edit .env — fill in SECRET_KEY, INTERNAL_SERVICE_TOKEN, ADMIN_PASSWORD,
# DJANGO_WEBHOOK_SECRET at minimum. Add API keys if you have them.

docker compose up --build
```

Then:
- Dashboard: http://localhost:8080 (log in with `ADMIN_USERNAME`/`ADMIN_PASSWORD`)
- SIEM Engine API docs: http://localhost:8001/docs
- TIP Platform API docs: http://localhost:8002/docs
- AI Orchestrator API docs: http://localhost:8003/docs
- Response Engine API docs: http://localhost:8004/docs

Trigger a test alert (needs an analyst/admin JWT — get one via the
dashboard or `POST /auth/login`, then):
```bash
curl -X POST http://localhost:8001/simulate \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"attack_type": "brute_force"}'
```

### VS Code
Open the folder, use the integrated terminal, run the same
`docker compose up --build` command. No extra config needed.

### PowerShell
Identical command — `docker compose up --build` — as long as Docker
Desktop is running.

## What's still simulated / not wired to a real system

- **CrowdStrike, Django, VirusTotal**: all real integrations, but only
  *activate* when their respective env vars are set. Without them, the
  system runs in safe simulated/heuristic mode — this was already the
  established pattern in the codebase and wasn't changed.
- **Response actions** other than `isolate_host`/`restore_host`
  (block_ip, disable_account, quarantine_file, etc.) are simulated only
  — there's no real firewall/EDR/IAM integration wired up for those.
  Extending `shared/integrations.py` with real connectors for those
  follows the same pattern as `CrowdStrikeConnector`.
- **Token refresh / rotation**: JWTs expire after
  `ACCESS_TOKEN_EXPIRE_MINUTES` (default 8h) and there's no refresh
  endpoint — re-login when it expires.
- **Rate limiting**: not implemented on any endpoint.

## Security notes

- Rotate the leaked VirusTotal key (see top of this doc).
- Change the default admin password immediately.
- Set strong, unique values for `SECRET_KEY`, `INTERNAL_SERVICE_TOKEN`,
  and `DJANGO_WEBHOOK_SECRET` before running this anywhere but
  localhost — the defaults in `.env.example` are intentionally
  insecure placeholders.
- `.env` is gitignored. Never commit real credentials.
