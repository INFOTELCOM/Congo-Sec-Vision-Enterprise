-- Keep this migration in sync with the Supabase project migration
-- enable_soc_realtime_and_api_schema.
-- Expose the soc schema through PostgREST and stream operational SOC changes.
do $$
declare t text;
begin
  foreach t in array array[
    'assets','events','vulnerabilities','software','log_findings','incidents',
    'approvals','workflows','ai_agents','ai_reports','hypervisor_inventory',
    'cve_intelligence','network_discoveries','cve_history',
    'cve_subscriptions','cve_notifications'
  ] loop
    if not exists (
      select 1 from pg_publication_tables
      where pubname = 'supabase_realtime'
        and schemaname = 'soc' and tablename = t
    ) then
      execute format('alter publication supabase_realtime add table soc.%I', t);
    end if;
  end loop;
end $$;

alter role authenticator set pgrst.db_schemas = 'public, soc';
notify pgrst, 'reload config';
