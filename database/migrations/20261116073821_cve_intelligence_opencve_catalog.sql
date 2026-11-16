-- Persist NVD and OpenCVE intelligence separately from asset-scoped findings.
create table if not exists soc.cve_intelligence (
  cve_id text primary key,
  nvd_payload jsonb not null default '{}'::jsonb,
  opencve_payload jsonb not null default '{}'::jsonb,
  opencve_history jsonb not null default '[]'::jsonb,
  sources text[] not null default array['NVD']::text[],
  nvd_fetched_at timestamptz,
  opencve_fetched_at timestamptz,
  history_fetched_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint cve_intelligence_id_format check (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$')
);
create index if not exists cve_intelligence_updated_at_idx
  on soc.cve_intelligence (updated_at desc);
create index if not exists cve_intelligence_sources_idx
  on soc.cve_intelligence using gin (sources);
alter table soc.cve_intelligence enable row level security;
grant usage on schema soc to authenticated;
grant select, insert, update on soc.cve_intelligence to authenticated;
drop policy if exists cve_intelligence_read_soc_roles on soc.cve_intelligence;
create policy cve_intelligence_read_soc_roles on soc.cve_intelligence
  for select to authenticated
  using (soc.has_soc_role(array['admin','analyst','viewer','incident_responder']));
drop policy if exists cve_intelligence_write_analysts on soc.cve_intelligence;
create policy cve_intelligence_write_analysts on soc.cve_intelligence
  for all to authenticated
  using (soc.has_soc_role(array['admin','analyst']))
  with check (soc.has_soc_role(array['admin','analyst']));
drop policy if exists cve_intelligence_delete_admin on soc.cve_intelligence;
create policy cve_intelligence_delete_admin on soc.cve_intelligence
  for delete to authenticated
  using (soc.has_soc_role(array['admin']));
