-- Lock down legacy public-schema duplicates. All 14 tables were verified empty
-- and the current web console uses Supabase Auth rather than direct public-table queries.
alter table public.agent_tokens enable row level security;
alter table public.ai_agents enable row level security;
alter table public.ai_reports enable row level security;
alter table public.approvals enable row level security;
alter table public.assets enable row level security;
alter table public.audit_logs enable row level security;
alter table public.events enable row level security;
alter table public.incidents enable row level security;
alter table public.log_findings enable row level security;
alter table public.software enable row level security;
alter table public.system_settings enable row level security;
alter table public.team_members enable row level security;
alter table public.vulnerabilities enable row level security;
alter table public.workflows enable row level security;

revoke all on all tables in schema public from anon;
grant select on all tables in schema public to authenticated;
grant insert, update on public.assets, public.events, public.vulnerabilities,
  public.software, public.log_findings, public.ai_agents, public.ai_reports to authenticated;
grant insert, update on public.incidents, public.approvals, public.team_members,
  public.workflows, public.system_settings, public.agent_tokens to authenticated;
grant insert on public.audit_logs to authenticated;
grant usage, select on all sequences in schema public to authenticated;

drop policy if exists legacy_agent_tokens_admin on public.agent_tokens;
create policy legacy_agent_tokens_admin on public.agent_tokens for all to authenticated
  using (soc.has_soc_role(array['admin'])) with check (soc.has_soc_role(array['admin']));

drop policy if exists legacy_assets_read on public.assets;
create policy legacy_assets_read on public.assets for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','viewer','incident_responder']));
drop policy if exists legacy_assets_write on public.assets;
create policy legacy_assets_write on public.assets for all to authenticated
  using (soc.has_soc_role(array['admin','analyst'])) with check (soc.has_soc_role(array['admin','analyst']));

drop policy if exists legacy_events_read on public.events;
create policy legacy_events_read on public.events for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','viewer','incident_responder']));
drop policy if exists legacy_events_write on public.events;
create policy legacy_events_write on public.events for all to authenticated
  using (soc.has_soc_role(array['admin','analyst'])) with check (soc.has_soc_role(array['admin','analyst']));

drop policy if exists legacy_vulnerabilities_read on public.vulnerabilities;
create policy legacy_vulnerabilities_read on public.vulnerabilities for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','viewer','incident_responder']));
drop policy if exists legacy_vulnerabilities_write on public.vulnerabilities;
create policy legacy_vulnerabilities_write on public.vulnerabilities for all to authenticated
  using (soc.has_soc_role(array['admin','analyst'])) with check (soc.has_soc_role(array['admin','analyst']));

drop policy if exists legacy_software_read on public.software;
create policy legacy_software_read on public.software for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','viewer','incident_responder']));
drop policy if exists legacy_software_write on public.software;
create policy legacy_software_write on public.software for all to authenticated
  using (soc.has_soc_role(array['admin','analyst'])) with check (soc.has_soc_role(array['admin','analyst']));

drop policy if exists legacy_log_findings_read on public.log_findings;
create policy legacy_log_findings_read on public.log_findings for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','viewer','incident_responder']));
drop policy if exists legacy_log_findings_write on public.log_findings;
create policy legacy_log_findings_write on public.log_findings for all to authenticated
  using (soc.has_soc_role(array['admin','analyst'])) with check (soc.has_soc_role(array['admin','analyst']));

drop policy if exists legacy_ai_agents_read on public.ai_agents;
create policy legacy_ai_agents_read on public.ai_agents for select to authenticated
  using (soc.has_soc_role(array['admin','analyst']));
drop policy if exists legacy_ai_agents_write on public.ai_agents;
create policy legacy_ai_agents_write on public.ai_agents for all to authenticated
  using (soc.has_soc_role(array['admin','analyst'])) with check (soc.has_soc_role(array['admin','analyst']));

drop policy if exists legacy_ai_reports_read on public.ai_reports;
create policy legacy_ai_reports_read on public.ai_reports for select to authenticated
  using (soc.has_soc_role(array['admin','analyst']));
drop policy if exists legacy_ai_reports_write on public.ai_reports;
create policy legacy_ai_reports_write on public.ai_reports for all to authenticated
  using (soc.has_soc_role(array['admin','analyst'])) with check (soc.has_soc_role(array['admin','analyst']));

drop policy if exists legacy_incidents_read on public.incidents;
create policy legacy_incidents_read on public.incidents for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','viewer','incident_responder']));
drop policy if exists legacy_incidents_write on public.incidents;
create policy legacy_incidents_write on public.incidents for all to authenticated
  using (soc.has_soc_role(array['admin','analyst','incident_responder']))
  with check (soc.has_soc_role(array['admin','analyst','incident_responder']));

drop policy if exists legacy_audit_admin_read on public.audit_logs;
create policy legacy_audit_admin_read on public.audit_logs for select to authenticated
  using (soc.has_soc_role(array['admin']));
drop policy if exists legacy_audit_analyst_insert on public.audit_logs;
create policy legacy_audit_analyst_insert on public.audit_logs for insert to authenticated
  with check (soc.has_soc_role(array['admin','analyst']));

drop policy if exists legacy_team_admin on public.team_members;
create policy legacy_team_admin on public.team_members for all to authenticated
  using (soc.has_soc_role(array['admin'])) with check (soc.has_soc_role(array['admin']));

drop policy if exists legacy_approvals_read on public.approvals;
create policy legacy_approvals_read on public.approvals for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','incident_responder']));
drop policy if exists legacy_approvals_insert on public.approvals;
create policy legacy_approvals_insert on public.approvals for insert to authenticated
  with check (soc.has_soc_role(array['admin','analyst','incident_responder']));
drop policy if exists legacy_approvals_update on public.approvals;
create policy legacy_approvals_update on public.approvals for update to authenticated
  using (soc.has_soc_role(array['admin'])) with check (soc.has_soc_role(array['admin']));

drop policy if exists legacy_workflows_read on public.workflows;
create policy legacy_workflows_read on public.workflows for select to authenticated
  using (soc.has_soc_role(array['admin','analyst']));
drop policy if exists legacy_workflows_write on public.workflows;
create policy legacy_workflows_write on public.workflows for all to authenticated
  using (soc.has_soc_role(array['admin'])) with check (soc.has_soc_role(array['admin']));

drop policy if exists legacy_system_settings_admin on public.system_settings;
create policy legacy_system_settings_admin on public.system_settings for all to authenticated
  using (soc.has_soc_role(array['admin'])) with check (soc.has_soc_role(array['admin']));
