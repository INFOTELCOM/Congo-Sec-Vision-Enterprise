-- Grant DELETE at the table level; the RLS policy restricts it to SOC admins.
grant delete on soc.cve_intelligence to authenticated;
