alter table public.events add column if not exists event_fingerprint text;
create unique index if not exists idx_events_event_fingerprint
  on public.events(event_fingerprint);
