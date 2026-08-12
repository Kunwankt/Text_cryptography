"""Firebase Firestore User Service.

Handles user registration, login, game progress tracking, and role-based
access control (admin vs regular users).

Users collection schema:
{
  "username": "string (unique, lowercase)",
  "password_hash": "SHA-256 hex (never plaintext)",
  "role": "admin | user",
  "display_name": "string",
  "created_at": "ISO timestamp",
  "last_login": "ISO timestamp",
  "device_ids": ["list of known device fingerprints"],
  "game_progress": {
    "total_xp": 0,
    "total_games_played": 0,
    "total_wins": 0,
    "daily_streak": 0,
    "last_daily_date": null,
    "best_scores": {"game_id": score},
    "crazy_mode_best": 0
  }
}
"""
from __future__ import annotations

import hashlib
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
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


# ---------------------------------------------------------------------------
# Admin bootstrap
# ---------------------------------------------------------------------------
def ensure_admin_exists() -> bool:
    """Ensure the admin user exists. If not, create it with ENCRYPTSYS112."""
    ref = _users_ref()
    if ref is None:
        logger.warning("Firebase unavailable — cannot create admin user.")
        return False
    try:
        with _FS_LOCK:
            admin_doc = ref.document("admin").get()
            if admin_doc.exists:
                logger.info("Admin user already exists in Firestore.")
                return True
            admin_data = {
                "username": "admin",
                "display_name": "System Administrator",
                "password_hash": hash_password("ENCRYPTSYS112"),
                "role": "admin",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_login": None,
                "device_ids": [],
                "game_progress": {
                    "total_xp": 0,
                    "total_games_played": 0,
                    "total_wins": 0,
                    "daily_streak": 0,
                    "last_daily_date": None,
                    "best_scores": {},
                    "crazy_mode_best": 0,
                },
            }
            ref.document("admin").set(admin_data)
            logger.info("Admin user created successfully (username=admin, password=ENCRYPTSYS112).")
            return True
    except Exception as exc:
        logger.warning("ensure_admin_exists failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Register / login / session helpers
# ---------------------------------------------------------------------------
def register_user(username: str, password: str, display_name: Optional[str] = None) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Register a new regular user. Returns (success, message, user_doc)."""
    ref = _users_ref()
    if ref is None:
        return False, "Database unavailable. Try again later.", None

    norm_user = normalize_username(username)
    if len(norm_user) < USERNAME_MIN_LEN:
        return False, f"Username must be at least {USERNAME_MIN_LEN} characters.", None

    if len(password or "") < PASSWORD_MIN_LEN:
        return False, f"Password must be at least {PASSWORD_MIN_LEN} characters.", None

    if norm_user == "admin":
        return False, "Username 'admin' is reserved.", None

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
                "game_progress": {
                    "total_xp": 0,
                    "total_games_played": 0,
                    "total_wins": 0,
                    "daily_streak": 0,
                    "last_daily_date": None,
                    "best_scores": {},
                    "crazy_mode_best": 0,
                },
            }
            ref.document(norm_user).set(user_data)
            return True, "Registration successful!", user_data
    except Exception as exc:
        logger.warning("register_user failed: %s", exc)
        return False, f"Registration error: {type(exc).__name__}", None


def authenticate_user(username: str, password: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Authenticate a user (admin or regular). Returns (ok, msg, user_doc)."""
    ref = _users_ref()
    if ref is None:
        return False, "Database unavailable.", None

    norm_user = normalize_username(username)
    if not norm_user:
        return False, "Username required.", None

    expected_hash = hash_password(password)

    try:
        with _FS_LOCK:
            doc = ref.document(norm_user).get()
            if not doc.exists:
                time.sleep(0.15)  # slow down brute force
                return False, "Invalid username or password.", None
            data = doc.to_dict() or {}
            if str(data.get("password_hash") or "") != expected_hash:
                time.sleep(0.15)
                return False, "Invalid username or password.", None

            # Update last_login timestamp
            ref.document(norm_user).update({
                "last_login": datetime.now(timezone.utc).isoformat()
            })
            data["last_login"] = datetime.now(timezone.utc).isoformat()
            return True, "Login successful.", data
    except Exception as exc:
        logger.warning("authenticate_user failed: %s", exc)
        return False, f"Authentication error: {type(exc).__name__}", None


def get_user(username: str) -> Optional[Dict[str, Any]]:
    """Fetch a user document by normalized username. Returns None if not found."""
    ref = _users_ref()
    if ref is None:
        return None
    try:
        norm = normalize_username(username)
        doc = ref.document(norm).get()
        if not doc.exists:
            return None
        return doc.to_dict() or {}
    except Exception as exc:
        logger.warning("get_user(%s) failed: %s", username, exc)
        return None


def update_game_progress(username: str, patch: Dict[str, Any]) -> bool:
    """Merge a patch into the user's game_progress map."""
    ref = _users_ref()
    if ref is None or not patch:
        return False
    try:
        norm = normalize_username(username)
        with _FS_LOCK:
            doc_ref = ref.document(norm)
            existing = doc_ref.get()
            if not existing.exists:
                return False
            current = (existing.to_dict() or {}).get("game_progress") or {}
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
    except Exception as exc:
        logger.warning("update_game_progress(%s) failed: %s", username, exc)
        return False


def record_device_id(username: str, device_id: str) -> bool:
    """Record a device id for a user (deduplicated)."""
    ref = _users_ref()
    if ref is None or not device_id:
        return False
    try:
        norm = normalize_username(username)
        with _FS_LOCK:
            doc_ref = ref.document(norm)
            existing = doc_ref.get()
            if not existing.exists:
                return False
            current = list((existing.to_dict() or {}).get("device_ids") or [])
            if device_id not in current:
                current.append(device_id)
                doc_ref.update({"device_ids": current})
        return True
    except Exception as exc:
        logger.warning("record_device_id failed: %s", exc)
        return False


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


def list_all_users() -> List[Dict[str, Any]]:
    """Admin-only: list all users (excluding password_hash)."""
    ref = _users_ref()
    if ref is None:
        return []
    try:
        results: List[Dict[str, Any]] = []
        with _FS_LOCK:
            for doc in ref.stream():
                d = doc.to_dict() or {}
                d.pop("password_hash", None)
                results.append(d)
        return results
    except Exception as exc:
        logger.warning("list_all_users failed: %s", exc)
        return []
