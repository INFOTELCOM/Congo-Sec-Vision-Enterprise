-- SOC role helper and least-privilege policies for the existing SOC schema.
-- Existing rows are not modified. Authenticated access is restricted by server-managed app_metadata.
create or replace function soc.has_soc_role(allowed_roles text[])
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select
    coalesce(auth.jwt() -> 'app_metadata' ->> 'csv_role',
             auth.jwt() -> 'app_metadata' ->> 'role', '') = any (allowed_roles)
    or coalesce(auth.jwt() -> 'app_metadata' -> 'roles', '[]'::jsonb) ?| allowed_roles;
$$;

grant usage on schema soc to authenticated;
grant execute on function soc.has_soc_role(text[]) to authenticated;
grant select on all tables in schema soc to authenticated;
grant usage, select on all sequences in schema soc to authenticated;

-- Sensitive agent token hashes are visible only to administrators.
grant insert, update on soc.agent_tokens to authenticated;
drop policy if exists agent_tokens_admin_select on soc.agent_tokens;
create policy agent_tokens_admin_select on soc.agent_tokens for select to authenticated
  using (soc.has_soc_role(array['admin']));
drop policy if exists agent_tokens_admin_insert on soc.agent_tokens;
create policy agent_tokens_admin_insert on soc.agent_tokens for insert to authenticated
  with check (soc.has_soc_role(array['admin']));
drop policy if exists agent_tokens_admin_update on soc.agent_tokens;
create policy agent_tokens_admin_update on soc.agent_tokens for update to authenticated
  using (soc.has_soc_role(array['admin'])) with check (soc.has_soc_role(array['admin']));

-- Profiles: users may read only their own profile; administrators may read all.
drop policy if exists profiles_self_or_admin_read on soc.profiles;
create policy profiles_self_or_admin_read on soc.profiles for select to authenticated
  using (user_id = auth.uid() or soc.has_soc_role(array['admin']));

-- General SOC telemetry and inventory.
grant insert, update on soc.assets, soc.events, soc.vulnerabilities,
  soc.software, soc.log_findings, soc.ai_agents, soc.ai_reports to authenticated;

drop policy if exists assets_soc_read on soc.assets;
create policy assets_soc_read on soc.assets for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','viewer','incident_responder']));
drop policy if exists assets_soc_write on soc.assets;
create policy assets_soc_write on soc.assets for all to authenticated
  using (soc.has_soc_role(array['admin','analyst']))
  with check (soc.has_soc_role(array['admin','analyst']));

drop policy if exists events_soc_read on soc.events;
create policy events_soc_read on soc.events for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','viewer','incident_responder']));
drop policy if exists events_soc_write on soc.events;
create policy events_soc_write on soc.events for all to authenticated
  using (soc.has_soc_role(array['admin','analyst']))
  with check (soc.has_soc_role(array['admin','analyst']));

drop policy if exists vulnerabilities_soc_read on soc.vulnerabilities;
create policy vulnerabilities_soc_read on soc.vulnerabilities for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','viewer','incident_responder']));
drop policy if exists vulnerabilities_soc_write on soc.vulnerabilities;
create policy vulnerabilities_soc_write on soc.vulnerabilities for all to authenticated
  using (soc.has_soc_role(array['admin','analyst']))
  with check (soc.has_soc_role(array['admin','analyst']));

drop policy if exists software_soc_read on soc.software;
create policy software_soc_read on soc.software for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','viewer','incident_responder']));
drop policy if exists software_soc_write on soc.software;
create policy software_soc_write on soc.software for all to authenticated
  using (soc.has_soc_role(array['admin','analyst']))
  with check (soc.has_soc_role(array['admin','analyst']));

drop policy if exists log_findings_soc_read on soc.log_findings;
create policy log_findings_soc_read on soc.log_findings for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','viewer','incident_responder']));
drop policy if exists log_findings_soc_write on soc.log_findings;
create policy log_findings_soc_write on soc.log_findings for all to authenticated
  using (soc.has_soc_role(array['admin','analyst']))
  with check (soc.has_soc_role(array['admin','analyst']));

-- Incident responders may create/update incident records.
grant insert, update on soc.incidents to authenticated;
drop policy if exists incidents_soc_read on soc.incidents;
create policy incidents_soc_read on soc.incidents for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','viewer','incident_responder']));
drop policy if exists incidents_soc_write on soc.incidents;
create policy incidents_soc_write on soc.incidents for all to authenticated
  using (soc.has_soc_role(array['admin','analyst','incident_responder']))
  with check (soc.has_soc_role(array['admin','analyst','incident_responder']));

-- Audit records are administrator-readable and analyst/admin insert-only.
grant insert on soc.audit_logs to authenticated;
drop policy if exists audit_logs_admin_read on soc.audit_logs;
create policy audit_logs_admin_read on soc.audit_logs for select to authenticated
  using (soc.has_soc_role(array['admin']));
drop policy if exists audit_logs_analyst_insert on soc.audit_logs;
create policy audit_logs_analyst_insert on soc.audit_logs for insert to authenticated
  with check (soc.has_soc_role(array['admin','analyst']));

-- Team management and workflows remain administrator-controlled.
grant insert, update on soc.team_members, soc.workflows to authenticated;
drop policy if exists team_members_admin_read on soc.team_members;
create policy team_members_admin_read on soc.team_members for select to authenticated
  using (soc.has_soc_role(array['admin']));
drop policy if exists team_members_admin_write on soc.team_members;
create policy team_members_admin_write on soc.team_members for all to authenticated
  using (soc.has_soc_role(array['admin'])) with check (soc.has_soc_role(array['admin']));

drop policy if exists workflows_soc_read on soc.workflows;
create policy workflows_soc_read on soc.workflows for select to authenticated
  using (soc.has_soc_role(array['admin','analyst']));
drop policy if exists workflows_admin_write on soc.workflows;
create policy workflows_admin_write on soc.workflows for all to authenticated
  using (soc.has_soc_role(array['admin'])) with check (soc.has_soc_role(array['admin']));

-- Approvals: incident-response roles may request; administrators alone may review/update.
grant insert, update on soc.approvals to authenticated;
drop policy if exists approvals_soc_read on soc.approvals;
create policy approvals_soc_read on soc.approvals for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','incident_responder']));
drop policy if exists approvals_soc_insert on soc.approvals;
create policy approvals_soc_insert on soc.approvals for insert to authenticated
  with check (soc.has_soc_role(array['admin','analyst','incident_responder']));
drop policy if exists approvals_admin_update on soc.approvals;
create policy approvals_admin_update on soc.approvals for update to authenticated
  using (soc.has_soc_role(array['admin'])) with check (soc.has_soc_role(array['admin']));

-- AI analysis and reports are analyst/admin controlled.
drop policy if exists ai_agents_soc_read on soc.ai_agents;
create policy ai_agents_soc_read on soc.ai_agents for select to authenticated
  using (soc.has_soc_role(array['admin','analyst']));
drop policy if exists ai_agents_soc_write on soc.ai_agents;
create policy ai_agents_soc_write on soc.ai_agents for all to authenticated
  using (soc.has_soc_role(array['admin','analyst'])) with check (soc.has_soc_role(array['admin','analyst']));

drop policy if exists ai_reports_soc_read on soc.ai_reports;
create policy ai_reports_soc_read on soc.ai_reports for select to authenticated
  using (soc.has_soc_role(array['admin','analyst']));
drop policy if exists ai_reports_soc_write on soc.ai_reports;
create policy ai_reports_soc_write on soc.ai_reports for all to authenticated
  using (soc.has_soc_role(array['admin','analyst'])) with check (soc.has_soc_role(array['admin','analyst']));

-- The hypervisor inventory policy is defined by the preceding additive migration.
