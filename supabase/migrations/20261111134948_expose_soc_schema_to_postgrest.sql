-- Expose the existing SOC schema through Supabase Data API.
-- Preserve the standard public and GraphQL schemas.
-- Existing grants and RLS policies on soc remain the authorization boundary.
ALTER ROLE authenticator SET pgrst.db_schemas = 'public,graphql_public,soc';

NOTIFY pgrst, 'reload config';
NOTIFY pgrst, 'reload schema';
