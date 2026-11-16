-- Keep read, insert, update and delete permissions separate to avoid
-- overlapping permissive policies on SELECT and DELETE.
drop policy if exists cve_intelligence_write_analysts on soc.cve_intelligence;
drop policy if exists cve_intelligence_insert_analysts on soc.cve_intelligence;
drop policy if exists cve_intelligence_update_analysts on soc.cve_intelligence;
create policy cve_intelligence_insert_analysts on soc.cve_intelligence
  for insert to authenticated
  with check (soc.has_soc_role(array['admin','analyst']));
create policy cve_intelligence_update_analysts on soc.cve_intelligence
  for update to authenticated
  using (soc.has_soc_role(array['admin','analyst']))
  with check (soc.has_soc_role(array['admin','analyst']));
