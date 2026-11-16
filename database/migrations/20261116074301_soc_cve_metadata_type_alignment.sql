-- Align text timestamps and global subscription rows with the legacy API model.
alter table soc.cve_subscriptions drop constraint if exists cve_subscriptions_asset_id_fkey;
alter table soc.vulnerabilities alter column published_at type text using published_at::text;
alter table soc.vulnerabilities alter column published_at set default '';
alter table soc.vulnerabilities alter column last_modified_at type text using last_modified_at::text;
alter table soc.vulnerabilities alter column last_modified_at set default '';
