CREATE EXTENSION IF NOT EXISTS refint;

DROP FUNCTION IF EXISTS register_player(TEXT, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS login_player(TEXT, TEXT);
DROP FUNCTION IF EXISTS session_player_id(TEXT);
DROP FUNCTION IF EXISTS create_session_for_player(INTEGER);

DROP TABLE IF EXISTS user_sessions CASCADE;
DROP TABLE IF EXISTS secrets CASCADE;
DROP TABLE IF EXISTS player_usernames CASCADE;
DROP TABLE IF EXISTS players CASCADE;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'flag_owner') THEN
        CREATE ROLE flag_owner NOLOGIN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
        CREATE ROLE app_user LOGIN PASSWORD 'fa4bc8e2f481cdf134b779eb1770bd317b52feb4b2fdd37ea41954fc0819977e';
    ELSE
        ALTER ROLE app_user WITH LOGIN PASSWORD 'fa4bc8e2f481cdf134b779eb1770bd317b52feb4b2fdd37ea41954fc0819977e';
    END IF;
END
$$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE ctf FROM PUBLIC;
GRANT CONNECT ON DATABASE ctf TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;

CREATE TABLE players (
    player_id SERIAL PRIMARY KEY,
    password TEXT NOT NULL,
    display_name TEXT NOT NULL,
    bio TEXT NOT NULL DEFAULT ''
);

CREATE TABLE player_usernames (
    username TEXT PRIMARY KEY,
    player_id INTEGER NOT NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    is_anchor BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK ((is_primary AND NOT is_anchor) OR (is_anchor AND NOT is_primary))
);

CREATE UNIQUE INDEX player_usernames_primary_idx
ON player_usernames (player_id)
WHERE is_primary;

CREATE UNIQUE INDEX player_usernames_anchor_idx
ON player_usernames (player_id)
WHERE is_anchor;

CREATE TABLE user_sessions (
    session_token TEXT PRIMARY KEY,
    player_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    profile_cache TEXT NOT NULL DEFAULT ''
);

CREATE INDEX user_sessions_player_id_idx ON user_sessions (player_id);
CREATE INDEX user_sessions_username_idx ON user_sessions (username);

CREATE TRIGGER player_usernames_refint_cascade
AFTER UPDATE OR DELETE ON player_usernames
FOR EACH ROW
EXECUTE FUNCTION check_foreign_key(1, 'cascade', 'username', 'user_sessions', 'username');

CREATE TRIGGER user_sessions_refint_validate
AFTER INSERT OR UPDATE ON user_sessions
FOR EACH ROW
EXECUTE FUNCTION check_primary_key('username', 'player_usernames', 'username');

CREATE TABLE secrets (
    owner_player_id INTEGER PRIMARY KEY,
    flag TEXT NOT NULL
);

ALTER TABLE secrets OWNER TO flag_owner;

REVOKE ALL ON players, player_usernames, user_sessions, secrets FROM PUBLIC;
REVOKE ALL ON players, player_usernames, user_sessions, secrets FROM app_user;

GRANT SELECT (player_id, display_name, bio) ON players TO app_user;
GRANT SELECT (username, player_id, is_primary, is_anchor) ON player_usernames TO app_user;
GRANT UPDATE (username) ON player_usernames TO app_user;
GRANT SELECT (session_token, player_id, username, profile_cache) ON user_sessions TO app_user;
GRANT UPDATE (username, profile_cache) ON user_sessions TO app_user;
GRANT SELECT (owner_player_id, flag) ON secrets TO app_user;

ALTER TABLE players ENABLE ROW LEVEL SECURITY;
ALTER TABLE players FORCE ROW LEVEL SECURITY;
ALTER TABLE player_usernames ENABLE ROW LEVEL SECURITY;
ALTER TABLE player_usernames FORCE ROW LEVEL SECURITY;
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets FORCE ROW LEVEL SECURITY;

CREATE POLICY players_select_policy
ON players
FOR SELECT
TO app_user
USING (player_id = current_setting('app.player_id', true)::integer);

CREATE POLICY player_usernames_select_policy
ON player_usernames
FOR SELECT
TO app_user
USING (player_id = current_setting('app.player_id', true)::integer);

CREATE POLICY player_usernames_update_policy
ON player_usernames
FOR UPDATE
TO app_user
USING (
    player_id = current_setting('app.player_id', true)::integer
    AND is_primary
)
WITH CHECK (player_id = current_setting('app.player_id', true)::integer);

CREATE POLICY user_sessions_select_policy
ON user_sessions
FOR SELECT
TO app_user
USING (player_id = current_setting('app.player_id', true)::integer);

CREATE POLICY user_sessions_update_policy
ON user_sessions
FOR UPDATE
TO app_user
USING (player_id = current_setting('app.player_id', true)::integer)
WITH CHECK (player_id = current_setting('app.player_id', true)::integer);

CREATE POLICY secrets_select_policy
ON secrets
FOR SELECT
TO app_user
USING (owner_player_id = current_setting('app.player_id', true)::integer);

CREATE OR REPLACE FUNCTION create_session_for_player(p_player_id INTEGER)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    new_token TEXT;
    primary_username TEXT;
BEGIN
    SELECT username
    INTO primary_username
    FROM public.player_usernames
    WHERE player_id = p_player_id AND is_primary;

    new_token := md5(random()::text || clock_timestamp()::text || p_player_id::text);

    INSERT INTO public.user_sessions (session_token, player_id, username, profile_cache)
    VALUES (
        new_token,
        p_player_id,
        primary_username,
        'Session preview is synchronized by a legacy PostgreSQL refint trigger.'
    );

    RETURN new_token;
END;
$$;

CREATE OR REPLACE FUNCTION register_player(
    p_username TEXT,
    p_password TEXT,
    p_display_name TEXT,
    p_bio TEXT,
    p_flag TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    new_player_id INTEGER;
BEGIN
    INSERT INTO public.players (password, display_name, bio)
    VALUES (p_password, p_display_name, p_bio)
    RETURNING player_id INTO new_player_id;

    INSERT INTO public.player_usernames (username, player_id, is_primary, is_anchor)
    VALUES
        (p_username, new_player_id, TRUE, FALSE),
        (p_username || '_anchor', new_player_id, FALSE, TRUE);

    INSERT INTO public.secrets (owner_player_id, flag)
    VALUES (new_player_id, p_flag);

    RETURN public.create_session_for_player(new_player_id);
END;
$$;

CREATE OR REPLACE FUNCTION login_player(
    p_username TEXT,
    p_password TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    found_player_id INTEGER;
BEGIN
    SELECT p.player_id
    INTO found_player_id
    FROM public.players AS p
    JOIN public.player_usernames AS u ON u.player_id = p.player_id
    WHERE u.username = p_username AND u.is_primary AND p.password = p_password;

    IF found_player_id IS NULL THEN
        RAISE EXCEPTION 'invalid credentials';
    END IF;

    RETURN public.create_session_for_player(found_player_id);
END;
$$;

CREATE OR REPLACE FUNCTION session_player_id(
    p_session_token TEXT
)
RETURNS INTEGER
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
    SELECT player_id
    FROM public.user_sessions
    WHERE session_token = p_session_token
$$;

REVOKE ALL ON FUNCTION create_session_for_player(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION register_player(TEXT, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION login_player(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION session_player_id(TEXT) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION register_player(TEXT, TEXT, TEXT, TEXT, TEXT) TO app_user;
GRANT EXECUTE ON FUNCTION login_player(TEXT, TEXT) TO app_user;
GRANT EXECUTE ON FUNCTION session_player_id(TEXT) TO app_user;
