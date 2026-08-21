-- Meant to expose only the safe profile columns. It is also writable.
--
-- The view runs as its OWNER (security_invoker is not set), it is over one
-- table with no aggregation so Postgres makes it AUTO-UPDATABLE, and on
-- Supabase the default privileges hand anon/authenticated write access to
-- every new object. GRANT SELECT does not make it read-only.
CREATE VIEW public.public_profiles AS
  SELECT id, display_name, avatar_url FROM public.users;

GRANT SELECT ON public.public_profiles TO anon, authenticated;
