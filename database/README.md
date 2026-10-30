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
