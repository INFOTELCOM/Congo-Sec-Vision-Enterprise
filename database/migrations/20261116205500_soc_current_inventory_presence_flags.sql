alter table public.software
  add column if not exists is_present boolean not null default true,
  add column if not exists first_seen timestamptz not null default now();
alter table public.soc_listening_ports
  add column if not exists is_current boolean not null default true;
create index if not exists idx_software_current_asset
  on public.software(asset_id,is_present,last_seen desc);
create index if not exists idx_soc_ports_current_ip
  on public.soc_listening_ports(ip_address,is_current,last_seen desc);
