-- WarpGen Supabase Setup Script (Secured Edition)
-- Run this in your Supabase SQL Editor to configure the database safely.

-- 1. Create the stats table
CREATE TABLE IF NOT EXISTS stats (
  id int PRIMARY KEY,
  total_generations int DEFAULT 0
);

-- 2. Insert the initial starting row
INSERT INTO stats (id, total_generations) 
VALUES (1, 0) 
ON CONFLICT (id) DO NOTHING;

-- 3. Create the v2_subscriptions table for personal links
CREATE TABLE IF NOT EXISTS v2_subscriptions (
    id text PRIMARY KEY,
    config_uri text NOT NULL,
    updated_at timestamptz DEFAULT now()
);

-- 4. Enable Row Level Security (RLS)
-- By enabling RLS and not creating public policies, we block all direct select/insert/update/delete
-- requests from the public "anon" API key.
ALTER TABLE stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE v2_subscriptions ENABLE ROW LEVEL SECURITY;

-- 5. Create secure function to increment the count
-- SECURITY DEFINER runs the function as the creator (postgres/owner), bypassing RLS on stats table.
-- SET search_path forces the function to use the public schema, preventing search_path hijack.
CREATE OR REPLACE FUNCTION increment_gen_count()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE stats
  SET total_generations = total_generations + 1
  WHERE id = 1;
END;
$$;

-- 6. Create secure function to update or create a subscription
CREATE OR REPLACE FUNCTION update_v2_subscription(p_id text, p_uri text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    INSERT INTO v2_subscriptions (id, config_uri, updated_at)
    VALUES (p_id, p_uri, now())
    ON CONFLICT (id) DO UPDATE
    SET config_uri = EXCLUDED.config_uri,
        updated_at = EXCLUDED.updated_at;
END;
$$;

-- 7. Restrict Access Control
-- Since all WarpGen operations occur via the FastAPI backend, we should restrict database
-- access entirely. The backend should use the Supabase 'service_role' key (which bypasses RLS),
-- while the public 'anon' key is granted zero access to prevent data scraping or modifications.

-- Revoke default public execution privileges on functions
REVOKE EXECUTE ON FUNCTION increment_gen_count() FROM public, anon, authenticated;
REVOKE EXECUTE ON FUNCTION update_v2_subscription(text, text) FROM public, anon, authenticated;

-- Grant execution privileges only to service_role (the backend)
GRANT EXECUTE ON FUNCTION increment_gen_count() TO service_role;
GRANT EXECUTE ON FUNCTION update_v2_subscription(text, text) TO service_role;

-- NOTE FOR CONFIGURATION:
-- In your backend .env file, configure SUPABASE_KEY using the "service_role" secret key
-- (found under Project Settings -> API in your Supabase dashboard).
-- Do NOT use the public "anon" key.

