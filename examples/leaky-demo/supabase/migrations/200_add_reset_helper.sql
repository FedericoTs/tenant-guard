CREATE OR REPLACE FUNCTION public.reset_workspace(p_ws uuid)
RETURNS void LANGUAGE sql SECURITY DEFINER AS $$
  DELETE FROM documents WHERE workspace_id = p_ws;
$$;
-- forgot to REVOKE EXECUTE FROM PUBLIC — anon can call this over PostgREST
