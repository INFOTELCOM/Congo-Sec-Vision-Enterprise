alter table public.vulnerabilities
  add column if not exists ssvc_json jsonb not null default '[]'::jsonb,
  add column if not exists assigned_to text not null default '',
  add column if not exists tags text[] not null default '{}';
create unique index if not exists idx_vulnerabilities_network_device_cve
  on public.vulnerabilities(network_device_id, cve_id);
