alter table public.software add column if not exists software_fingerprint text;
create unique index if not exists idx_software_asset_fingerprint
  on public.software(asset_id, software_fingerprint);
alter table public.soc_malware_detections add column if not exists dedupe_key text;
create unique index if not exists idx_soc_malware_dedupe
  on public.soc_malware_detections(dedupe_key);
