# Supabase — Congo Sec Vision Enterprise

Project Supabase: `gyxbkutmgcnsmytodfst`
Project URL: `https://gyxbkutmgcnsmytodfst.supabase.co`

## Database foundation

The `soc` schema contains the first PostgreSQL model corresponding to the current SQLite API:
assets, agent tokens, events, vulnerabilities, software inventory, detection findings,
incidents, audit logs, team members, approvals, workflows and user profiles.

The schema is intentionally private and is not exposed through the public Data API.
All twelve tables have Row Level Security enabled. No direct `anon` or `authenticated`
table grants are made. Only trusted server-side components using the Supabase
`service_role` may access these tables. Never put that key in Git, browser JavaScript,
an Android APK, or any other client.

## Identity and authorization model

- Supabase Auth will own email/password identity and sessions.
- `soc.profiles.user_id` links a Supabase Auth user to an application role.
- Allowed roles: `admin`, `analyst`, `viewer`, `incident_responder`.
- Role assignment must be performed by trusted administration code, never from
  user-editable metadata or a client-supplied role.
- Account creation should be invitation-only. Public self-registration must remain disabled.
- Agent enrollment remains a separate machine identity and must not reuse a human session.

## Important implementation status

This commit is the database foundation only. The current FastAPI service and web/Android
clients still use the legacy shared administrator bearer token. Do not switch users to
the new login screen until the API has been migrated to validate Supabase JWTs, enforce
roles, and use PostgreSQL for all application data. The existing SQLite database is not
automatically copied by this schema.

## Apply / verify

The schema has already been created in the Supabase project and verified there.
`schema.sql` is an idempotent reference snapshot for review and future environments.


## AI analysis and CVE synchronization (backend branch 0.4)

- Each authorized endpoint enrollment creates a logical `CSVA-AI-<asset>` assignment.
- The first endpoint analysis is queued after enrollment; active endpoints are re-analysed no more often than every 15 minutes on heartbeat.
- The SOC console exposes the per-machine agent list and individual report history, including log signals, inventory, CVE candidates and remediation advice.
- The LLM layer uses an OpenAI-compatible `/chat/completions` endpoint. Configure `LLM_BASE_URL`, `LLM_MODEL`, and (when required) `LLM_API_KEY` as backend secrets. No key belongs in the browser or mobile app. Without a provider, deterministic local rules remain active.
- NVD checks run periodically (default 24 hours) in rotating batches (default 25 software records). Set `NVD_API_KEY` to use the higher NVD request rate. Manual sync remains available to administrators.
- CVE keyword results are candidates. CPE and version-range matches are surfaced as stronger technical matches, not proof of exposure; vendor advisories, product editions and backported fixes must still be checked.
- Recommendations are advisory only. No patch or remote command is executed automatically.

Environment variables are documented in `.env.example`. The periodic worker runs in the FastAPI process; deploy a single API worker unless a distributed scheduler/lock is introduced, to avoid duplicate scheduled scans.
