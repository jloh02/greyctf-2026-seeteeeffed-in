import os
from contextlib import closing

import psycopg2
from psycopg2 import errors
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__)
DB_DSN = os.getenv("DB_DSN", "dbname=ctf user=app_user password=fa4bc8e2f481cdf134b779eb1770bd317b52feb4b2fdd37ea41954fc0819977e host=db")
FRONTEND_DIR = os.path.join(app.root_path, "frontend")
CHALLENGE_FLAG = os.getenv("CHALLENGE_FLAG", "flag{refint_cascade_update_sql_injection}")


def get_session_token() -> str | None:
    return request.headers.get("X-Session-Token")


def set_session_player(cur, session_token: str) -> int | None:
    cur.execute("SELECT session_player_id(%s);", (session_token,))
    row = cur.fetchone()
    if row is None or row[0] is None:
        return None

    cur.execute("SELECT set_config('app.player_id', %s, true);", (str(row[0]),))
    return row[0]


def fetch_session(cur, session_token: str):
    cur.execute(
        """
        SELECT
            s.session_token,
            s.player_id,
            primary_name.username,
            anchor_name.username,
            s.username,
            s.profile_cache,
            p.display_name,
            p.bio
        FROM user_sessions AS s
        JOIN players AS p ON p.player_id = s.player_id
        JOIN player_usernames AS primary_name
            ON primary_name.player_id = p.player_id AND primary_name.is_primary
        JOIN player_usernames AS anchor_name
            ON anchor_name.player_id = p.player_id AND anchor_name.is_anchor
        WHERE s.session_token = %s;
        """,
        (session_token,),
    )
    row = cur.fetchone()
    if row is None:
        return None

    return {
        "session_token": row[0],
        "player_id": row[1],
        "username": row[2],
        "anchor_username": row[3],
        "session_username": row[4],
        "profile_cache": row[5],
        "display_name": row[6],
        "bio": row[7],
    }


def require_profile(cur):
    session_token = get_session_token()
    if not session_token:
        return None, (
            jsonify({"status": "error", "message": "Missing session token."}),
            401,
        )

    player_id = set_session_player(cur, session_token)
    if player_id is None:
        return None, (jsonify({"status": "error", "message": "Unknown session."}), 404)

    profile = fetch_session(cur, session_token)
    if profile is None:
        return None, (jsonify({"status": "error", "message": "Unknown session."}), 404)

    return profile, None


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:path>")
def frontend(path: str):
    if path.startswith("api/"):
        return jsonify({"status": "error", "message": "Not found"}), 404

    candidate = os.path.join(FRONTEND_DIR, path)
    if os.path.isfile(candidate):
        return send_from_directory(FRONTEND_DIR, path)

    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/api")
def api_index():
    return jsonify(
        {
            "message": "Welcome to the Profile Sync API",
            "endpoints": [
                "POST /api/register",
                "POST /api/login",
                "GET /api/me",
                "POST /api/profile/rename",
            ],
        }
    )


@app.route("/api/register", methods=["POST"])
def register():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "")
    password = payload.get("password", "")
    display_name = payload.get("display_name", "") or username
    bio = payload.get("bio", "")

    if not isinstance(username, str) or not username or len(username) > 64:
        return jsonify({"status": "error", "message": "Username must be 1-64 characters."}), 400
    if not isinstance(password, str) or len(password) < 8 or len(password) > 128:
        return jsonify({"status": "error", "message": "Password must be 8-128 characters."}), 400
    if not isinstance(display_name, str) or not display_name or len(display_name) > 80:
        return jsonify({"status": "error", "message": "Display name must be 1-80 characters."}), 400
    if not isinstance(bio, str) or len(bio) > 240:
        return jsonify({"status": "error", "message": "Bio is too long."}), 400

    try:
        with closing(psycopg2.connect(DB_DSN)) as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT register_player(%s, %s, %s, %s, %s);",
                        (username, password, display_name, bio, CHALLENGE_FLAG),
                    )
                    session_token = cur.fetchone()[0]
                    set_session_player(cur, session_token)
                    profile = fetch_session(cur, session_token)
                    return jsonify(
                        {
                            "status": "success",
                            "data": {
                                "session_token": session_token,
                                "profile": profile,
                            },
                        }
                    )
    except errors.UniqueViolation:
        return jsonify({"status": "error", "message": "Username already exists."}), 409
    except Exception:
        return jsonify({"status": "error", "message": "Database error occurred."}), 500


@app.route("/api/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "")
    password = payload.get("password", "")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"status": "error", "message": "Invalid login request."}), 400

    try:
        with closing(psycopg2.connect(DB_DSN)) as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT login_player(%s, %s);", (username, password))
                    session_token = cur.fetchone()[0]
                    set_session_player(cur, session_token)
                    profile = fetch_session(cur, session_token)
                    return jsonify(
                        {
                            "status": "success",
                            "data": {
                                "session_token": session_token,
                                "profile": profile,
                            },
                        }
                    )
    except psycopg2.Error as exc:
        if "invalid credentials" in str(exc):
            return jsonify({"status": "error", "message": "Invalid credentials."}), 401
        return jsonify({"status": "error", "message": "Database error occurred."}), 500
    except Exception:
        return jsonify({"status": "error", "message": "Database error occurred."}), 500


@app.route("/api/me")
def api_me():
    try:
        with closing(psycopg2.connect(DB_DSN)) as conn:
            with conn, conn.cursor() as cur:
                profile, error_response = require_profile(cur)
                if error_response is not None:
                    return error_response

                return jsonify({"status": "success", "data": profile})
    except Exception:
        return jsonify({"status": "error", "message": "Database error occurred."}), 500


@app.route("/api/profile/rename", methods=["POST"])
def rename_profile():
    payload = request.get_json(silent=True) or {}
    new_username = payload.get("username", "")

    if not isinstance(new_username, str) or not new_username:
        return jsonify({"status": "error", "message": "Username is required."}), 400
    if len(new_username) > 160:
        return jsonify({"status": "error", "message": "Username is too long."}), 400

    try:
        with closing(psycopg2.connect(DB_DSN)) as conn:
            with conn:
                with conn.cursor() as cur:
                    profile, error_response = require_profile(cur)
                    if error_response is not None:
                        return error_response

                    cur.execute(
                        """
                        UPDATE player_usernames
                        SET username = %s
                        WHERE player_id = %s AND is_primary;
                        """,
                        (new_username, profile["player_id"]),
                    )

                    if cur.rowcount != 1:
                        return jsonify({"status": "error", "message": "Rename failed."}), 400

                    set_session_player(cur, profile["session_token"])
                    updated_profile = fetch_session(cur, profile["session_token"])
                    return jsonify({"status": "success", "data": updated_profile})
    except errors.UniqueViolation:
        return jsonify({"status": "error", "message": "Username already exists."}), 409
    except Exception:
        return jsonify({"status": "error", "message": "Database error occurred."}), 500


if __name__ == "__main__":
    print("Starting Web CTF challenge on port 5000...")
    app.run(host="0.0.0.0", port=5000)
