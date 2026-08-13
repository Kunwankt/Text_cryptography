"""Firebase Firestore User Service — with SQLite fallback for Render/hosted deployments.

Dual backend architecture:
- PRIMARY: Firebase Firestore (if firebase_config.db is configured)
- FALLBACK: Local SQLite users table (used when Firestore unavailable, e.g. Render free tier)

Callers use the same public API — backend selection is automatic.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from .firebase_config import db  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    db = None

logger = logging.getLogger(__name__)

USERS_COLLECTION = "users"
USERNAME_MIN_LEN = 3
PASSWORD_MIN_LEN = 6

_FS_LOCK = threading.Lock()

_SQLITE_LOCK = threading.Lock()
_SQLITE_INITIALIZED = False

# On Render, /var/data is persisted across deploys; locally fall back to project database/ dir.
def _sqlite_db_path() -> str:
    """Resolve the SQLite users DB path. Render-friendly: honor DATA_DIR env var."""
    data_dir = os.environ.get("DATA_DIR")
    if data_dir:
        base = Path(data_dir)
    else:
        base = Path(__file__).resolve().parent.parent / "database"
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning("Could not create users DB directory %s: %s", base, exc)
    return str(base / "users.db")


def _sqlite_conn() -> Optional[sqlite3.Connection]:
    """Return a new SQLite connection (or None on failure). Initializes schema first time."""
    global _SQLITE_INITIALIZED
    try:
        conn = sqlite3.connect(_sqlite_db_path(), timeout=5.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            # SQLite-level write locking via EXCLUSIVE mode prevents corruption under gunicorn
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
        except sqlite3.Error:
            pass
        if not _SQLITE_INITIALIZED:
            with _SQLITE_LOCK:
                if not _SQLITE_INITIALIZED:
                    try:
                        conn.executescript("""
                            CREATE TABLE IF NOT EXISTS users (
                                username         TEXT PRIMARY KEY,
                                display_name     TEXT NOT NULL DEFAULT '',
                                password_hash    TEXT NOT NULL,
                                role             TEXT NOT NULL DEFAULT 'user',
                                created_at       TEXT,
                                last_login       TEXT,
                                device_ids_json  TEXT NOT NULL DEFAULT '[]',
                                game_progress_json TEXT NOT NULL DEFAULT '{}'
                            );
                        """)
                        # Ensure admin row exists in SQLite fallback (same ENCRYPTSYS112)
                        cur = conn.execute("SELECT username FROM users WHERE username='admin'")
                        if not cur.fetchone():
                            default_gp = {
                                "total_xp": 0, "total_games_played": 0, "total_wins": 0,
                                "daily_streak": 0, "last_daily_date": None,
                                "best_scores": {}, "crazy_mode_best": 0,
                            }
                            conn.execute(
                                "INSERT INTO users(username,display_name,password_hash,role,created_at,device_ids_json,game_progress_json) VALUES(?,?,?,?,?,?,?)",
                                (
                                    "admin",
                                    "System Administrator",
                                    hash_password("ENCRYPTSYS112"),
                                    "admin",
                                    datetime.now(timezone.utc).isoformat(),
                                    "[]",
                                    json.dumps(default_gp),
                                ),
                            )
                        _SQLITE_INITIALIZED = True
                        logger.info("SQLite users table initialized at %s", _sqlite_db_path())
                    except sqlite3.Error as exc:
                        logger.warning("SQLite users init failed: %s", exc)
        return conn
    except sqlite3.Error as exc:
        logger.warning("SQLite users connection failed: %s", exc)
        return None


def _user_doc_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert SQLite row into the same dict shape Firestore produces."""
    d: Dict[str, Any] = {
        "username": str(row["username"]),
        "display_name": str(row["display_name"] or ""),
        "password_hash": str(row["password_hash"]),
        "role": str(row["role"] or "user"),
        "created_at": row["created_at"] and str(row["created_at"]),
        "last_login": row["last_login"] and str(row["last_login"]),
    }
    try:
        d["device_ids"] = json.loads(str(row["device_ids_json"] or "[]"))
    except (TypeError, json.JSONDecodeError):
        d["device_ids"] = []
    try:
        gp = json.loads(str(row["game_progress_json"] or "{}"))
        if not isinstance(gp, dict):
            gp = {}
    except (TypeError, json.JSONDecodeError):
        gp = {}
    # Guarantee all game_progress fields exist (mirror Firestore doc default shape)
    gp.setdefault("total_xp", 0)
    gp.setdefault("total_games_played", 0)
    gp.setdefault("total_wins", 0)
    gp.setdefault("daily_streak", 0)
    gp.setdefault("last_daily_date", None)
    gp.setdefault("best_scores", {})
    gp.setdefault("crazy_mode_best", 0)
    d["game_progress"] = gp
    return d


def _sqlite_default_game_progress() -> Dict[str, Any]:
    return {
        "total_xp": 0, "total_games_played": 0, "total_wins": 0,
        "daily_streak": 0, "last_daily_date": None,
        "best_scores": {}, "crazy_mode_best": 0,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """SHA-256 password hashing (salted with a site-wide pepper)."""
    pepper = "ENCRYPTSYS_SITE_PEPPER_2026"
    combined = (pepper + str(password or "")).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def generate_device_id() -> str:
    """Generate a stable-ish device fingerprint (NOT cryptographic — for UX only)."""
    return uuid.uuid4().hex[:16]


def normalize_username(username: str) -> str:
    """Username normalization: lowercase + strip."""
    return (username or "").strip().lower()


def _users_ref():
    if db is None:
        return None
    return db.collection(USERS_COLLECTION)


def _firestore_available() -> bool:
    if db is None:
        return False
    try:
        _ = db.collection("users")
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Admin bootstrap
# ---------------------------------------------------------------------------
def ensure_admin_exists() -> bool:
    """Ensure the admin user exists in Firestore (primary) AND SQLite (fallback)."""
    ok_fs = False
    ref = _users_ref()
    if ref is not None:
        try:
            with _FS_LOCK:
                admin_doc = ref.document("admin").get()
                if admin_doc.exists:
                    logger.info("Admin user already exists in Firestore.")
                    ok_fs = True
                else:
                    admin_data = {
                        "username": "admin",
                        "display_name": "System Administrator",
                        "password_hash": hash_password("ENCRYPTSYS112"),
                        "role": "admin",
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "last_login": None,
                        "device_ids": [],
                        "game_progress": _sqlite_default_game_progress(),
                    }
                    ref.document("admin").set(admin_data)
                    logger.info("Admin user created successfully (username=admin, password=ENCRYPTSYS112).")
                    ok_fs = True
        except Exception as exc:
            logger.warning("Firestore ensure_admin_exists failed: %s", exc)

    ok_sql = False
    conn = _sqlite_conn()
    if conn is not None:
        try:
            with _SQLITE_LOCK:
                cur = conn.execute("SELECT username FROM users WHERE username='admin'")
                if cur.fetchone():
                    ok_sql = True
                else:
                    gp = _sqlite_default_game_progress()
                    conn.execute(
                        "INSERT INTO users(username,display_name,password_hash,role,created_at,device_ids_json,game_progress_json) VALUES(?,?,?,?,?,?,?)",
                        (
                            "admin", "System Administrator", hash_password("ENCRYPTSYS112"),
                            "admin", datetime.now(timezone.utc).isoformat(),
                            "[]", json.dumps(gp),
                        ),
                    )
                    logger.info("SQLite admin fallback row created (username=admin, password=ENCRYPTSYS112).")
                    ok_sql = True
        except sqlite3.Error as exc:
            logger.warning("SQLite ensure_admin_exists failed: %s", exc)
        finally:
            try:
                conn.close()
            except Exception:
                pass
    return ok_fs or ok_sql


# ---------------------------------------------------------------------------
# Register / login / session helpers
# ---------------------------------------------------------------------------
def _register_user_sqlite(norm_user: str, password: str, display_name: Optional[str]) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    if len(norm_user) < USERNAME_MIN_LEN:
        return False, f"Username must be at least {USERNAME_MIN_LEN} characters.", None
    if len(password or "") < PASSWORD_MIN_LEN:
        return False, f"Password must be at least {PASSWORD_MIN_LEN} characters.", None
    if norm_user == "admin":
        return False, "Username 'admin' is reserved.", None
    conn = _sqlite_conn()
    if conn is None:
        return False, "User database unavailable.", None
    try:
        with _SQLITE_LOCK:
            cur = conn.execute("SELECT username FROM users WHERE username=?", (norm_user,))
            if cur.fetchone():
                return False, f"Username '{norm_user}' is already taken.", None
            gp = _sqlite_default_game_progress()
            user_data = {
                "username": norm_user,
                "display_name": (display_name or norm_user).strip() or norm_user,
                "password_hash": hash_password(password),
                "role": "user",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_login": None,
                "device_ids": [],
                "game_progress": gp,
            }
            conn.execute(
                "INSERT INTO users(username,display_name,password_hash,role,created_at,device_ids_json,game_progress_json) VALUES(?,?,?,?,?,?,?)",
                (
                    norm_user, user_data["display_name"], user_data["password_hash"],
                    "user", user_data["created_at"], "[]", json.dumps(gp),
                ),
            )
            logger.info("SQLite registered new user: %s", norm_user)
            return True, "Registration successful!", user_data
    except sqlite3.Error as exc:
        logger.warning("SQLite register_user failed: %s", exc)
        return False, f"Registration error: {type(exc).__name__}", None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def register_user(username: str, password: str, display_name: Optional[str] = None) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Register a new regular user. Firestore first, falls back to SQLite."""
    norm_user = normalize_username(username)
    if len(norm_user) < USERNAME_MIN_LEN:
        return False, f"Username must be at least {USERNAME_MIN_LEN} characters.", None
    if len(password or "") < PASSWORD_MIN_LEN:
        return False, f"Password must be at least {PASSWORD_MIN_LEN} characters.", None
    if norm_user == "admin":
        return False, "Username 'admin' is reserved.", None

    ref = _users_ref()
    if ref is not None:
        try:
            with _FS_LOCK:
                existing = ref.document(norm_user).get()
                if existing.exists:
                    return False, f"Username '{norm_user}' is already taken.", None
                user_data = {
                    "username": norm_user,
                    "display_name": (display_name or norm_user).strip() or norm_user,
                    "password_hash": hash_password(password),
                    "role": "user",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "last_login": None,
                    "device_ids": [],
                    "game_progress": _sqlite_default_game_progress(),
                }
                ref.document(norm_user).set(user_data)
                return True, "Registration successful!", user_data
        except Exception as exc:
            logger.warning("Firestore register_user failed, falling back to SQLite: %s", exc)

    return _register_user_sqlite(norm_user, password, display_name)


def _synthetic_admin(expected_hash: str, note: str) -> Tuple[bool, str, Dict[str, Any]]:
    synthetic = {
        "username": "admin",
        "display_name": "System Administrator",
        "password_hash": expected_hash,
        "role": "admin",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_login": datetime.now(timezone.utc).isoformat(),
        "device_ids": [],
        "game_progress": _sqlite_default_game_progress(),
    }
    logger.warning("authenticate_user: using synthetic admin fallback (%s).", note)
    return True, "Login successful (local fallback, no Firestore write).", synthetic


def _authenticate_user_sqlite(norm_user: str, password: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    if not norm_user:
        return False, "Username required.", None
    expected_hash = hash_password(password)
    conn = _sqlite_conn()
    if conn is None:
        if norm_user == "admin" and expected_hash == hash_password("ENCRYPTSYS112"):
            return _synthetic_admin(expected_hash, "SQLite unavailable — in-memory hash check")
        return False, "User database unavailable.", None
    try:
        with _SQLITE_LOCK:
            cur = conn.execute(
                "SELECT * FROM users WHERE username=?", (norm_user,)
            )
            row = cur.fetchone()
            if row is None:
                time.sleep(0.15)
                if norm_user == "admin" and expected_hash == hash_password("ENCRYPTSYS112"):
                    return _synthetic_admin(expected_hash, "SQLite admin row missing — in-memory hash check")
                return False, "Invalid username or password.", None
            data = _user_doc_from_row(row)
            if str(data.get("password_hash") or "") != expected_hash:
                time.sleep(0.15)
                return False, "Invalid username or password.", None

            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute("UPDATE users SET last_login=? WHERE username=?", (now_iso, norm_user))
            data["last_login"] = now_iso
            return True, "Login successful.", data
    except sqlite3.Error as exc:
        logger.warning("SQLite authenticate_user failed: %s", exc)
        if norm_user == "admin" and expected_hash == hash_password("ENCRYPTSYS112"):
            return _synthetic_admin(expected_hash, f"SQLite error {type(exc).__name__} — in-memory hash check")
        return False, f"Authentication error: {type(exc).__name__}", None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def authenticate_user(username: str, password: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Authenticate a user (admin or regular). Firestore first, SQLite fallback.

    Hard constraint: admin/ENCRYPTSYS112 must ALWAYS succeed via synthetic
    fallback as last resort (prevents admin lockout).
    """
    norm_user = normalize_username(username)
    if not norm_user:
        return False, "Username required.", None

    expected_hash = hash_password(password)
    is_admin_login = (norm_user == "admin") and (expected_hash == hash_password("ENCRYPTSYS112"))

    ref = _users_ref()
    if ref is not None:
        try:
            with _FS_LOCK:
                doc = ref.document(norm_user).get()
                if not doc.exists:
                    if is_admin_login:
                        return _synthetic_admin(expected_hash, "Firestore admin doc missing")
                    time.sleep(0.15)
                    # Fall through to SQLite before giving up for regular users
                    raise RuntimeError("user doc missing — try SQLite")
                data = doc.to_dict() or {}
                if str(data.get("password_hash") or "") != expected_hash:
                    time.sleep(0.15)
                    return False, "Invalid username or password.", None

                ref.document(norm_user).update({
                    "last_login": datetime.now(timezone.utc).isoformat()
                })
                data["last_login"] = datetime.now(timezone.utc).isoformat()
                return True, "Login successful.", data
        except Exception as exc:
            if is_admin_login and "user doc missing" in str(exc):
                pass  # already handled above
            elif not _firestore_available():
                logger.warning("Firestore unavailable for authenticate_user: %s", exc)
            else:
                logger.warning("Firestore authenticate_user failed, falling back to SQLite: %s", exc)

    return _authenticate_user_sqlite(norm_user, password)


def _get_user_sqlite(username: str) -> Optional[Dict[str, Any]]:
    norm = normalize_username(username)
    if not norm:
        return None
    conn = _sqlite_conn()
    if conn is None:
        return None
    try:
        with _SQLITE_LOCK:
            cur = conn.execute("SELECT * FROM users WHERE username=?", (norm,))
            row = cur.fetchone()
            if row is None:
                return None
            return _user_doc_from_row(row)
    except sqlite3.Error as exc:
        logger.warning("SQLite get_user(%s) failed: %s", username, exc)
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_user(username: str) -> Optional[Dict[str, Any]]:
    """Fetch a user document by normalized username. Firestore first, SQLite fallback."""
    ref = _users_ref()
    if ref is not None:
        try:
            norm = normalize_username(username)
            doc = ref.document(norm).get()
            if doc.exists:
                return doc.to_dict() or {}
        except Exception as exc:
            if _firestore_available():
                logger.warning("Firestore get_user(%s) failed: %s", username, exc)
    return _get_user_sqlite(username)


def _broken_streak_check_progress(gp: Dict[str, Any]) -> Dict[str, Any]:
    """If last_daily_date was NOT yesterday/today, reset daily_streak to 0.

    In-place mutates ``gp`` and also returns it for convenience.
    """
    import datetime as _dt
    try:
        last_str = gp.get("last_daily_date")
        if not last_str or not isinstance(last_str, str):
            return gp
        today = _dt.date.today()
        yesterday = today - _dt.timedelta(days=1)
        try:
            last = _dt.date.fromisoformat(last_str)
        except (ValueError, TypeError):
            return gp
        if last != today and last != yesterday:
            gp["daily_streak"] = 0
    except Exception:
        pass
    return gp


def _update_game_progress_sqlite(username: str, patch: Dict[str, Any]) -> bool:
    if not patch:
        return False
    norm = normalize_username(username)
    if not norm:
        return False
    conn = _sqlite_conn()
    if conn is None:
        return False
    try:
        with _SQLITE_LOCK:
            cur = conn.execute("SELECT game_progress_json FROM users WHERE username=?", (norm,))
            row = cur.fetchone()
            if row is None:
                return False
            try:
                current = json.loads(str(row["game_progress_json"] or "{}"))
                if not isinstance(current, dict):
                    current = {}
            except (TypeError, json.JSONDecodeError):
                current = {}
            current = _broken_streak_check_progress(current)
            for k, v in patch.items():
                if isinstance(v, dict) and isinstance(current.get(k), dict):
                    sub = dict(current[k])
                    sub.update(v)
                    current[k] = sub
                else:
                    current[k] = v
            conn.execute(
                "UPDATE users SET game_progress_json=? WHERE username=?",
                (json.dumps(current), norm),
            )
            logger.info("SQLite updated game_progress for %s", norm)
            return True
    except sqlite3.Error as exc:
        logger.warning("SQLite update_game_progress(%s) failed: %s", username, exc)
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def update_game_progress(username: str, patch: Dict[str, Any]) -> bool:
    """Merge a patch into the user's game_progress map. Firestore first, SQLite fallback."""
    ref = _users_ref()
    if ref is not None or not patch:
        try:
            norm = normalize_username(username)
            with _FS_LOCK:
                doc_ref = ref.document(norm)
                existing = doc_ref.get()
                if existing.exists:
                    current = (existing.to_dict() or {}).get("game_progress") or {}
                    current = _broken_streak_check_progress(dict(current))
                    merged = dict(current)
                    for k, v in patch.items():
                        if isinstance(v, dict) and isinstance(current.get(k), dict):
                            sub = dict(current[k])
                            sub.update(v)
                            merged[k] = sub
                        else:
                            merged[k] = v
                    doc_ref.update({"game_progress": merged})
                    return True
                # Firestore user doesn't exist — fall through to SQLite (may be SQLite-only account)
        except Exception as exc:
            if _firestore_available():
                logger.warning("Firestore update_game_progress(%s) failed, falling back to SQLite: %s", username, exc)
    return _update_game_progress_sqlite(username, patch)


def _record_device_id_sqlite(username: str, device_id: str) -> bool:
    if not device_id:
        return False
    norm = normalize_username(username)
    if not norm:
        return False
    conn = _sqlite_conn()
    if conn is None:
        return False
    try:
        with _SQLITE_LOCK:
            cur = conn.execute("SELECT device_ids_json FROM users WHERE username=?", (norm,))
            row = cur.fetchone()
            if row is None:
                return False
            try:
                current = json.loads(str(row["device_ids_json"] or "[]"))
                if not isinstance(current, list):
                    current = []
            except (TypeError, json.JSONDecodeError):
                current = []
            if device_id not in current:
                current.append(device_id)
                conn.execute(
                    "UPDATE users SET device_ids_json=? WHERE username=?",
                    (json.dumps(current), norm),
                )
        return True
    except sqlite3.Error as exc:
        logger.warning("SQLite record_device_id failed: %s", exc)
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def record_device_id(username: str, device_id: str) -> bool:
    """Record a device id for a user (deduplicated). Firestore first, SQLite fallback."""
    ref = _users_ref()
    if ref is not None and device_id:
        try:
            norm = normalize_username(username)
            with _FS_LOCK:
                doc_ref = ref.document(norm)
                existing = doc_ref.get()
                if existing.exists:
                    current = list((existing.to_dict() or {}).get("device_ids") or [])
                    if device_id not in current:
                        current.append(device_id)
                        doc_ref.update({"device_ids": current})
                    return True
        except Exception as exc:
            if _firestore_available():
                logger.warning("Firestore record_device_id failed, falling back to SQLite: %s", exc)
    return _record_device_id_sqlite(username, device_id)


# ---------------------------------------------------------------------------
# Session / user-context helpers
# ---------------------------------------------------------------------------
def current_session_user(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Given Flask session dict, return the user doc or None."""
    try:
        username = session.get("username")
        if not username:
            return None
        ts = session.get("login_at") or 0
        if ts and (time.time() - float(ts)) > (60 * 60 * 8):  # 8h session TTL
            return None
        return get_user(username)
    except Exception:
        return None


def is_admin(user_doc: Optional[Dict[str, Any]]) -> bool:
    """Return True if user_doc has role == 'admin'."""
    if not user_doc:
        return False
    return str(user_doc.get("role") or "user").lower() == "admin"


def _list_all_users_sqlite() -> List[Dict[str, Any]]:
    conn = _sqlite_conn()
    if conn is None:
        return []
    try:
        with _SQLITE_LOCK:
            cur = conn.execute("SELECT * FROM users ORDER BY username")
            rows = cur.fetchall()
        results: List[Dict[str, Any]] = []
        for r in rows:
            d = _user_doc_from_row(r)
            d.pop("password_hash", None)
            results.append(d)
        return results
    except sqlite3.Error as exc:
        logger.warning("SQLite list_all_users failed: %s", exc)
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass


def list_all_users() -> List[Dict[str, Any]]:
    """Admin-only: list all users (excluding password_hash). Firestore first, SQLite fallback."""
    ref = _users_ref()
    if ref is not None:
        try:
            results: List[Dict[str, Any]] = []
            with _FS_LOCK:
                for doc in ref.stream():
                    d = doc.to_dict() or {}
                    d.pop("password_hash", None)
                    results.append(d)
            if results:
                return results
        except Exception as exc:
            if _firestore_available():
                logger.warning("Firestore list_all_users failed, falling back to SQLite: %s", exc)
    return _list_all_users_sqlite()


def _list_users_for_leaderboard_sqlite(limit: int) -> List[Dict[str, Any]]:
    conn = _sqlite_conn()
    if conn is None:
        return []
    try:
        with _SQLITE_LOCK:
            cur = conn.execute("SELECT * FROM users ORDER BY username")
            rows = cur.fetchall()
        rows_data: List[Dict[str, Any]] = []
        for r in rows:
            try:
                d = _user_doc_from_row(r)
                d.pop("password_hash", None)
                d.pop("device_ids", None)
                gp = d.get("game_progress") if isinstance(d.get("game_progress"), dict) else {}
                bs = gp.get("best_scores") if isinstance(gp.get("best_scores"), dict) else {}
                xp_v = int(gp.get("total_xp") or 0)
                wins_v = int(gp.get("total_wins") or 0)
                streak_v = int(gp.get("daily_streak") or 0)
                cm_best = int(bs.get("crazy_mode_best") or bs.get("crazy_mode") or 0)
                uname = str(d.get("username") or "")
                rows_data.append({
                    "username": uname,
                    "display_name": str(d.get("display_name") or uname or "Anonymous"),
                    "is_admin": str(d.get("role") or "user").lower() == "admin",
                    "rank": None,
                    "xp": xp_v,
                    "wins": wins_v,
                    "streak": streak_v,
                    "crazy_best": cm_best,
                    "best_scores": {"crazy_mode_best": cm_best},
                    "daily_streak": streak_v,
                    "total_xp": xp_v,
                    "total_wins": wins_v,
                })
            except Exception:
                continue
        rows_data.sort(key=lambda r: (-int(r.get("xp") or 0), -int(r.get("streak") or 0)))
        safe_limit = max(1, min(int(limit or 20), 100))
        return rows_data[:safe_limit]
    except sqlite3.Error as exc:
        logger.warning("SQLite list_users_for_leaderboard failed: %s", exc)
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass


def list_users_for_leaderboard(limit: int = 20) -> List[Dict[str, Any]]:
    """PUBLIC SAFE: list top N users by XP for leaderboard. Firestore + SQLite union."""
    # 1) Firestore (may return empty)
    rows_fs: List[Dict[str, Any]] = []
    ref = _users_ref()
    if ref is not None:
        try:
            with _FS_LOCK:
                for doc in ref.stream():
                    d = doc.to_dict() or {}
                    for _k in ("password_hash", "device_ids", "email", "last_login_ip"):
                        d.pop(_k, None)
                    gp = d.get("game_progress") if isinstance(d.get("game_progress"), dict) else {}
                    bs = gp.get("best_scores") if isinstance(gp.get("best_scores"), dict) else {}
                    xp_v = int(gp.get("total_xp") or 0)
                    wins_v = int(gp.get("total_wins") or 0)
                    streak_v = int(gp.get("daily_streak") or 0)
                    cm_best = int(bs.get("crazy_mode_best") or bs.get("crazy_mode") or 0)
                    uname = str(d.get("username") or "")
                    rows_fs.append({
                        "username": uname,
                        "display_name": str(d.get("display_name") or uname or "Anonymous"),
                        "is_admin": str(d.get("role") or "user").lower() == "admin",
                        "rank": None,
                        "xp": xp_v,
                        "wins": wins_v,
                        "streak": streak_v,
                        "crazy_best": cm_best,
                        "best_scores": {"crazy_mode_best": cm_best},
                        "daily_streak": streak_v,
                        "total_xp": xp_v,
                        "total_wins": wins_v,
                    })
            rows_fs.sort(key=lambda r: (-int(r.get("xp") or 0), -int(r.get("streak") or 0)))
        except Exception as exc:
            if _firestore_available():
                logger.warning("Firestore list_users_for_leaderboard failed: %s", exc)
            rows_fs = []

    # 2) SQLite
    rows_sql = _list_users_for_leaderboard_sqlite(limit=max(3, int(limit)))

    # 3) Union by username, SQLite values take precedence when username overlaps
    by_uname: Dict[str, Dict[str, Any]] = {}
    for r in rows_fs:
        u = str(r.get("username") or "")
        if u:
            by_uname[u] = r
    for r in rows_sql:
        u = str(r.get("username") or "")
        if u:
            by_uname[u] = r
    merged = list(by_uname.values())
    merged.sort(key=lambda r: (-int(r.get("xp") or 0), -int(r.get("streak") or 0)))
    safe_limit = max(1, min(int(limit or 20), 100))
    return merged[:safe_limit]
