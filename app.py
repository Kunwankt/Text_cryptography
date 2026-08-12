import os
import sqlite3
import time
import base64
import logging
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, send_file, make_response, send_from_directory
from flask_wtf.csrf import CSRFProtect
from config import Config
from crypto.aes import AES256Cipher
from crypto.des import DESCipher
from crypto.rsa import RSACipher
from crypto.hashing import HashGenerator
from crypto.key_generator import KeyGenerator
from utils.validators import validate_aes_key, validate_des_key, validate_not_empty
from utils.helpers import export_history_to_csv, export_history_to_json
from utils.rainbow_lookup import generate_educational_payload, total_entries
from routes.attack_routes import attack_bp
from routes.games_routes import bp as games_bp
from routes.auth_routes import auth_bp
from firebase.user_service import (
    current_session_user as _fw_current_user,
    ensure_admin_exists,
    is_admin as _fw_is_admin,
    list_all_users,
    update_game_progress,
    record_device_id,
    generate_device_id,
)
from flask import session as flask_session

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
csrf = CSRFProtect(app)

app.register_blueprint(attack_bp)
app.register_blueprint(games_bp)
app.register_blueprint(auth_bp)

_ADMIN_BOOTSTRAPPED = False

# ---------------------------------------------------------------------------
# Firebase / Firestore (optional). Only writes when configured.
# ---------------------------------------------------------------------------
FIRESTORE_PROJECT_ID: str | None = None
FIRESTORE_IMPORTED_FS = None
try:
    from firebase.firebase_config import db as FIRESTORE_DB  # type: ignore
    from firebase.firebase_config import project_id as _fb_project_id  # type: ignore
    try:
        from firebase_admin import firestore as _fs  # type: ignore  # noqa: WPS433
        FIRESTORE_IMPORTED_FS = _fs
    except Exception:  # pragma: no cover
        FIRESTORE_IMPORTED_FS = None
    FIRESTORE_PROJECT_ID = _fb_project_id
    if FIRESTORE_DB is None:
        logger.warning(
            "Firebase/Firestore not configured (firebase_config.db == None). "
            "All logs stay in local SQLite only. Check: (1) pip install firebase-admin "
            "(2) FIREBASE_SERVICE_ACCOUNT_JSON env var OR firebase-key.json in project root. "
            "Restart app after fixing."
        )
except Exception as exc:  # noqa: BLE001
    FIRESTORE_DB = None
    logger.warning(
        "Firebase module import FAILED (%s: %s) — continuing with local-only SQLite history. "
        "Fix the import error above then restart the Flask app to enable Firestore sync.",
        type(exc).__name__, str(exc),
    )
FIRESTORE_COLLECTION = "encryption_history"
LOG_SOURCE = "text-encryption-flask-app"


def timestamp_to_str(ts):
    """Convert Unix timestamp to human-readable string"""
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


app.add_template_filter(timestamp_to_str, 'timestamp_to_str')


def _ensure_db_dir():
    """Ensure the parent directory of the SQLite database file exists before attempting to connect.

    Without this, sqlite3.connect() raises `sqlite3.OperationalError:
    'unable to open database file' when the folder is missing.
    """
    db_path = app.config['DATABASE_PATH']
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.isdir(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
        except OSError as exc:
            logger.error("Failed to create DB directory %s: %s", db_dir, exc)
            return False
    return True


def init_db():
    """Initialize SQLite database.

    Returns True on success, False on failure. Any exceptions are caught and logged
    so startup does not propagate DB errors up to callers.
    """
    if not _ensure_db_dir():
        return False
    conn = None
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS history
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      algorithm TEXT NOT NULL,
                      operation TEXT NOT NULL,
                      timestamp REAL NOT NULL)''')
        conn.commit()
        logger.info("Database initialized successfully")
        return True
    except (sqlite3.Error, OSError) as exc:
        logger.error("Database initialization failed: %s", exc)
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error as exc:
                logger.warning("Failed to close DB connection after init_db: %s", exc)


def _ensure_history_table(conn: sqlite3.Connection) -> None:
    """Lazy, idempotent history table bootstrap + column migrations.

    Creates the history table if missing. For databases created with the
    older 4-column schema, it safely ALTER TABLE to add newer metadata
    columns (content_length, client_ip, status, synced_firebase,
    firestore_doc_id). All operations use "ADD COLUMN IF NOT EXISTS" style
    short-circuits so repeated calls are harmless.
    """
    try:
        conn.execute(
            '''CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT NOT NULL,
                operation TEXT NOT NULL,
                timestamp REAL NOT NULL
            )'''
        )
        conn.commit()
    except sqlite3.Error as exc:
        logger.warning("Failed to create base history table: %s", exc)
        return

    # --- Idempotent column migrations -----------------------------------------------------
    migration_columns = [
        ("content_length", "INTEGER DEFAULT 0"),
        ("client_ip",    "TEXT DEFAULT ''"),
        ("status",       "TEXT DEFAULT 'success'"),
        ("synced_firebase", "INTEGER DEFAULT 0"),
        ("firestore_doc_id",  "TEXT DEFAULT ''"),
        ("owner_username", "TEXT DEFAULT ''"),
        ("owner_device_id", "TEXT DEFAULT ''"),
    ]
    try:
        cursor = conn.execute("PRAGMA table_info(history)")
        existing_cols = {row[1] for row in cursor.fetchall()}
    except sqlite3.Error as exc:
        logger.warning("Could not inspect history columns: %s", exc)
        existing_cols = set()

    for col_name, col_spec in migration_columns:
        if col_name in existing_cols:
            continue
        try:
            conn.execute(f"ALTER TABLE history ADD COLUMN {col_name} {col_spec}")
            conn.commit()
            logger.info("History schema: added column %s", col_name)
        except sqlite3.Error as exc:
            # "duplicate column name" = harmless; anything else we log only
            if "duplicate" not in str(exc).lower():
                logger.warning("Could not add history column %s: %s", col_name, exc)


try:
    import atexit as _atexit
    _ensure_db_dir()
    init_db()
    _ok = ensure_admin_exists()
    if _ok:
        _ADMIN_BOOTSTRAPPED = True
        logger.info("Admin bootstrap: admin/ENCRYPTSYS112 user ensured in Firestore users collection.")
    else:
        logger.warning("Admin bootstrap skipped (Firebase unavailable). Admin login will still work once Firebase is up.")
except Exception as _ae:
    logger.warning("Admin bootstrap exception (ignored): %s", _ae)


def _get_client_ip() -> str:
    """Best-effort client IP for auditing (never logged to plaintext files)."""
    try:
        if request.headers.getlist("X-Forwarded-For"):
            return request.headers.getlist("X-Forwarded-For")[0].split(",")[0].strip()
        return request.remote_addr or ""
    except RuntimeError:
        return ""


def _current_user_doc():
    """Return currently-authenticated user dict or None."""
    try:
        return _fw_current_user(flask_session)
    except Exception:
        return None


def _current_is_admin() -> bool:
    """Return True if current session has admin role."""
    return _fw_is_admin(_current_user_doc())


def _current_username() -> str:
    """Return normalized username if logged in, else ''."""
    u = _current_user_doc()
    return str((u or {}).get("username") or "").strip().lower()


def _get_or_create_device_id() -> str:
    """Read device_id from cookie or generate a new one (doesn't set cookie)."""
    try:
        from flask import request as _req
        cid = (_req.cookies.get("encryptsys_device_id") or "").strip()
        if cid:
            return cid
    except Exception:
        pass
    try:
        return generate_device_id()
    except Exception:
        return "unknown-" + str(int(time.time() * 1000))


def _resolve_history_ownership_filters():
    """For history queries: return (where_clause_str, params_list) to enforce user-scope.

    ADMIN -> no filter.
    LOGGED-IN USER -> owner_username match OR owner_device_id match.
    GUEST -> only owner_device_id match (cookie based, no username).
    """
    if _current_is_admin():
        return "", []
    uname = _current_username()
    did = _get_or_create_device_id()
    if uname and did:
        return " WHERE (owner_username = ? OR owner_device_id = ?)", [uname, did]
    if uname:
        return " WHERE owner_username = ?", [uname]
    if did:
        return " WHERE owner_device_id = ?", [did]
    # Worst case: restrict to nothing so guests can't read cross-user data
    return " WHERE 1 = 0", []


def _firestore_add_history(doc_id: str, payload: dict) -> bool:
    """Firestore write — best-effort, returns True only when succeeded.

    ALWAYS ensures the 9 required top-level fields exist, per project spec:
      algorithm, operation, client_ip, content_length,
      local_time, execution_time, source, status, timestamp.

    ``timestamp`` uses ``firestore.SERVER_TIMESTAMP`` when available so the
    Firestore console shows a real, queryable Timestamp (not a float / string).
    ``local_time`` is an ISO-8601 string wall-clock snapshot from the server.
    ``execution_time`` is seconds (float), rounded to 6 decimals.
    """
    if FIRESTORE_DB is None:
        return False

    try:
        # Build final payload guaranteeing every required field.
        safe_payload: dict = {}
        safe_payload["algorithm"] = str(payload.get("algorithm") or "unknown")
        safe_payload["operation"] = str(payload.get("operation") or "unknown")
        safe_payload["client_ip"] = str(payload.get("client_ip") or "")
        safe_payload["content_length"] = int(payload.get("content_length") or 0)
        safe_payload["local_time"] = str(
            payload.get("local_time")
            or datetime.now(timezone.utc).isoformat(timespec="seconds")
        )
        try:
            safe_payload["execution_time"] = round(
                float(payload.get("execution_time") or 0.0), 6
            )
        except (TypeError, ValueError):
            safe_payload["execution_time"] = 0.0
        safe_payload["source"] = str(payload.get("source") or LOG_SOURCE)
        status_val = str(payload.get("status") or "Success")
        if status_val.lower() == "success":
            status_val = "Success"
        elif status_val.lower() in ("failed", "failure", "error"):
            status_val = "Failed"
        safe_payload["status"] = status_val

        # Timestamp: prefer firestore SERVER_TIMESTAMP so it is a true Firestore
        # Timestamp type, sortable/queryable in Firestore console.
        if FIRESTORE_IMPORTED_FS is not None:
            safe_payload["timestamp"] = FIRESTORE_IMPORTED_FS.SERVER_TIMESTAMP
        else:
            # Final fallback: use a timezone-aware datetime string
            safe_payload["timestamp"] = datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            )

        # Preserve any legacy/debug metadata (optional extras) if it won't clash
        for key in ("local_id", "timestamp_iso", "client_ip_hash",
                    "synced_firebase", "firestore_doc_id",
                    "firebase_doc_id", "notes"):
            if key in payload and key not in safe_payload:
                safe_payload[key] = payload[key]

        # firestore.client().collection(c).document(id).set(payload)
        FIRESTORE_DB.collection(FIRESTORE_COLLECTION).document(doc_id).set(safe_payload)
        logger.info(
            "Firestore synced entry %s/%s (exec=%.4fs len=%d ip=%s)",
            safe_payload.get("algorithm"),
            safe_payload.get("operation"),
            float(safe_payload.get("execution_time") or 0.0),
            int(safe_payload.get("content_length") or 0),
            safe_payload.get("client_ip") or "-",
        )
        return True
    except Exception as exc:  # noqa: BLE001
        # Ensure silent Firebase exceptions are still surfaced in server logs
        # (and NOT swallowed silently).
        logger.warning(
            "Firestore write FAILED for doc_id=%s algo=%s op=%s :: "
            "exception_type=%s message=%s",
            doc_id,
            payload.get("algorithm"),
            payload.get("operation"),
            type(exc).__name__,
            str(exc),
            exc_info=True,
        )
        return False


def add_to_history(
    algorithm,
    operation,
    content_length: int = 0,
    status: str = "success",
    client_ip: str | None = None,
    execution_time: float = 0.0,
    local_time_iso: str | None = None,
    source: str | None = None,
    doc_id_override: str | None = None,
    owner_username_override: str | None = None,
    owner_device_id_override: str | None = None,
):
    """Add entry to SQLite history AND (optionally) Firebase Firestore.

    This is ALWAYS called AFTER a successful encrypt/decrypt/hash operation.
    The caller SHOULD pass:
      - ``client_ip``       : from ``_get_client_ip()``
      - ``execution_time``  : ``end - start`` from ``time.perf_counter()``
      - ``local_time_iso``  : ISO-8601 snapshot taken during the request
    If any are omitted we still compute sensible defaults so Firestore NEVER
    receives an empty required field.

    This is best-effort — any exception is swallowed + logged; the caller
    (encrypt/decrypt/hash APIs) continues to succeed even when logging is
    unavailable, so users never lose their operation result.

    Returns dict with
      ``{sqlite: bool, firestore: bool|None, id: int|None, synced_firebase: 0|1,
         doc_id: str|None, client_ip: str, execution_time: float}``
    so callers (API responses) can introspect what actually happened and
    surface logging-sync status in HTTP responses for verification/testing.
    """
    result = {
        "sqlite": False,
        "firestore": None,
        "id": None,
        "synced_firebase": 0,
        "doc_id": None,
        "client_ip": "",
        "execution_time": max(0.0, float(execution_time or 0.0)),
        "local_time": "",
    }
    if not _ensure_db_dir():
        return result

    ts = time.time()

    # --- Resolve all required fields (use explicit arg if provided else fallback) ---
    resolved_ip = client_ip if client_ip is not None else _get_client_ip()
    result["client_ip"] = str(resolved_ip or "")

    if local_time_iso:
        resolved_local_time = str(local_time_iso)
    else:
        # Capture once and reuse so SQLite + Firestore agree exactly.
        resolved_local_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result["local_time"] = resolved_local_time

    resolved_exec = max(0.0, float(execution_time or 0.0))
    resolved_status = str(status or "success")
    resolved_source = str(source or LOG_SOURCE)

    conn = None
    local_id = None
    doc_id = None
    resolved_owner_username = str(owner_username_override or _current_username() or "")
    resolved_owner_device_id = str(owner_device_id_override or _get_or_create_device_id() or "")
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        _ensure_history_table(conn)
        c = conn.cursor()
        c.execute(
            '''INSERT INTO history
               (algorithm, operation, timestamp, content_length, client_ip, status, synced_firebase, firestore_doc_id,
                owner_username, owner_device_id)
               VALUES (?, ?, ?, ?, ?, ?, 0, '', ?, ?)''',
            (
                algorithm,
                operation,
                ts,
                int(content_length or 0),
                result["client_ip"],
                resolved_status,
                resolved_owner_username,
                resolved_owner_device_id,
            ),
        )
        local_id = c.lastrowid
        conn.commit()
        result["sqlite"] = True
        result["id"] = local_id
    except (sqlite3.Error, OSError) as exc:
        logger.error(
            "SQLite history insert FAILED [%s/%s]: %s (exc_type=%s)",
            algorithm, operation, exc, type(exc).__name__,
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error as exc:
                logger.warning("Failed to close DB after add_to_history: %s", exc)

    # --- Firestore mirror (optional, but ALWAYS attempt with full 9 fields) ---
    if local_id is not None and FIRESTORE_DB is not None:
        # Stable doc id so re-runs don't create duplicates.  If caller
        # explicitly overrides (e.g. retry uploads), honor that.
        if doc_id_override:
            doc_id = str(doc_id_override)
        else:
            doc_id = f"{int(ts * 1000)}-{local_id}-{algorithm}"

        fs_payload = {
            "local_id": local_id,
            "algorithm": algorithm,
            "operation": operation,
            "timestamp": ts,  # used only by old query paths; overridden below
            "timestamp_iso": datetime.fromtimestamp(ts).isoformat(timespec="seconds"),
            "content_length": int(content_length or 0),
            "client_ip": result["client_ip"],
            "status": resolved_status,
            "source": resolved_source,
            "local_time": resolved_local_time,
            "execution_time": resolved_exec,
            "owner_username": resolved_owner_username,
            "owner_device_id": resolved_owner_device_id,
        }
        synced = _firestore_add_history(doc_id, fs_payload)
        result["firestore"] = bool(synced)
        result["synced_firebase"] = 1 if synced else 0
        result["doc_id"] = doc_id if synced else ""

        # Reflect sync status back to SQLite for UI badges (for dashboard + history pages)
        if synced and _ensure_db_dir():
            try:
                conn2 = sqlite3.connect(app.config['DATABASE_PATH'])
                try:
                    conn2.execute(
                        "UPDATE history SET synced_firebase = 1, firestore_doc_id = ? WHERE id = ?",
                        (doc_id, local_id),
                    )
                    conn2.commit()
                finally:
                    conn2.close()
            except sqlite3.Error as exc:
                logger.warning("Could not mark history %s as synced: %s", local_id, exc)

    return result


def _row_to_dict(cursor_cols, row) -> dict:
    """Map sqlite3 row to dict by column name — safe against schema upgrades."""
    data = dict(zip(cursor_cols, row))
    # Normalize + provide sensible defaults for pre-migration rows
    return {
        "id": data.get("id"),
        "algorithm": data.get("algorithm", ""),
        "operation": data.get("operation", ""),
        "timestamp": data.get("timestamp", 0.0),
        "content_length": int(data.get("content_length") or 0),
        "client_ip": data.get("client_ip") or "",
        "status": data.get("status") or "success",
        "synced_firebase": bool(data.get("synced_firebase") or 0),
        "firestore_doc_id": data.get("firestore_doc_id") or "",
        "owner_username": data.get("owner_username") or "",
        "owner_device_id": data.get("owner_device_id") or "",
    }


def get_history(limit: int | None = None):
    """Get history entries (newest first), scoped to current user/device unless admin.

    Returns ``[]`` on any DB failure (page renders still succeed)."""
    if not _ensure_db_dir():
        return []
    conn = None
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        conn.row_factory = sqlite3.Row
        _ensure_history_table(conn)
        c = conn.cursor()
        where_str, params = _resolve_history_ownership_filters()
        query = 'SELECT * FROM history' + where_str + ' ORDER BY timestamp DESC'
        if limit and int(limit) > 0:
            query += f' LIMIT {int(limit)}'
        c.execute(query, params)
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
        return [_row_to_dict(cols, tuple(r)) for r in rows]
    except (sqlite3.Error, OSError) as exc:
        logger.error("Failed to load history from DB: %s", exc)
        return []
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error as exc:
                logger.warning("Failed to close DB connection after get_history: %s", exc)


def delete_history_entry(entry_id):
    """Delete a history entry from SQLite and, when possible, from Firestore.

    ADMIN-ONLY: returns False if caller is not admin (for route-level use,
    route handlers should check first and return 403).
    """
    if not _ensure_db_dir():
        return False
    if not _current_is_admin():
        logger.warning("delete_history_entry blocked: caller is not admin (entry_id=%s)", entry_id)
        return False
    conn = None
    firestore_doc = ""
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        _ensure_history_table(conn)
        c = conn.cursor()
        c.execute("SELECT firestore_doc_id FROM history WHERE id = ?", (entry_id,))
        row = c.fetchone()
        if row and row[0]:
            firestore_doc = row[0]
        c.execute('DELETE FROM history WHERE id = ?', (entry_id,))
        conn.commit()
    except (sqlite3.Error, OSError) as exc:
        logger.error("Failed to delete history entry %s: %s", entry_id, exc)
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error as exc:
                logger.warning("Failed to close DB connection after delete_history_entry: %s", exc)

    if firestore_doc and FIRESTORE_DB is not None:
        try:
            FIRESTORE_DB.collection(FIRESTORE_COLLECTION).document(firestore_doc).delete()
            logger.info("Deleted Firestore doc %s", firestore_doc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not delete Firestore doc %s: %s", firestore_doc, exc)
    return True


def clear_history():
    """Clear ALL local history. If Firestore is configured, deletes ALL docs too.

    ADMIN-ONLY: returns False if caller is not admin (route handlers should check first).
    """
    if not _ensure_db_dir():
        return False
    if not _current_is_admin():
        logger.warning("clear_history blocked: caller is not admin")
        return False
    all_docs: list[str] = []
    conn = None
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        _ensure_history_table(conn)
        c = conn.cursor()
        if FIRESTORE_DB is not None:
            try:
                c.execute("SELECT firestore_doc_id FROM history WHERE firestore_doc_id <> ''")
                all_docs = [r[0] for r in c.fetchall()]
            except sqlite3.Error:
                all_docs = []
        c.execute('DELETE FROM history')
        conn.commit()
    except (sqlite3.Error, OSError) as exc:
        logger.error("Failed to clear history: %s", exc)
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error as exc:
                logger.warning("Failed to close DB connection after clear_history: %s", exc)

    if all_docs and FIRESTORE_DB is not None:
        for doc in all_docs:
            try:
                FIRESTORE_DB.collection(FIRESTORE_COLLECTION).document(doc).delete()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not delete Firestore doc %s during clear: %s", doc, exc)
        logger.info("Firestore cleared %s history documents", len(all_docs))
    return True


@app.context_processor
def inject_globals():
    synced_count = 0
    local_count = 0
    total_count = 0
    try:
        all_history = get_history() if _ensure_db_dir() else []
        total_count = len(all_history)
        for h in all_history:
            if bool(h.get("synced_firebase")):
                synced_count += 1
            else:
                local_count += 1
    except Exception:  # noqa: BLE001
        pass
    user_doc = _current_user_doc()
    is_authed = bool(user_doc)
    is_admin_role = _fw_is_admin(user_doc)
    safe_user = None
    if user_doc:
        safe_user = {
            "username": user_doc.get("username"),
            "display_name": user_doc.get("display_name"),
            "role": user_doc.get("role", "user"),
        }
    return {
        "firebase_configured": FIRESTORE_DB is not None,
        "firebase_project_id": FIRESTORE_PROJECT_ID,
        "firestore_collection": FIRESTORE_COLLECTION,
        "history_counts": {
            "total": total_count,
            "synced_firebase": synced_count,
            "local_only": local_count,
        },
        "current_user": safe_user,
        "is_authenticated": is_authed,
        "is_admin": bool(is_admin_role),
    }


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/google8f0ce872da7fe93a.html')
def google_site_verification():
    return send_from_directory(app.root_path, 'google8f0ce872da7fe93a.html')


@app.route('/dashboard')
def dashboard():
    history = get_history()
    rainbow_counts = total_entries()
    return render_template(
        'dashboard.html',
        history=history,
        rainbow_counts=rainbow_counts,
        firebase_configured=FIRESTORE_DB is not None,
    )


@app.route('/encrypt')
def encrypt_page():
    return render_template('encrypt.html')


@app.route('/decrypt')
def decrypt_page():
    return render_template('decrypt.html')


@app.route('/history')
def history_page():
    history = get_history()
    return render_template(
        'history.html',
        history=history,
        firebase_configured=FIRESTORE_DB is not None,
    )


@app.route('/education')
def education_page():
    return render_template('education.html')


@app.route('/api/encrypt/aes', methods=['POST'])
def encrypt_aes():
    try:
        data = request.get_json()
        plaintext = data.get('plaintext', '')
        key_b64 = data.get('key', '')

        # Validate inputs
        valid, msg = validate_not_empty(plaintext, "Plaintext")
        if not valid:
            return jsonify({'success': False, 'error': msg}), 400
        valid, msg = validate_aes_key(key_b64)
        if not valid:
            return jsonify({'success': False, 'error': msg}), 400

        client_ip = _get_client_ip()
        request_local_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
        key = base64.b64decode(key_b64)

        _t0 = time.perf_counter()
        ciphertext = AES256Cipher.encrypt(plaintext, key)
        _t1 = time.perf_counter()
        exec_time = max(0.0, _t1 - _t0)

        logging_result = add_to_history(
            'AES-256',
            'Encrypt',
            content_length=len(plaintext),
            status='success',
            client_ip=client_ip,
            execution_time=exec_time,
            local_time_iso=request_local_time,
        )

        response_body = {
            'success': True,
            'ciphertext': ciphertext,
            'execution_time_ms': round(exec_time * 1000, 3),
            'logging': {
                'sqlite': bool(logging_result.get('sqlite', False)),
                'firestore': logging_result.get('firestore'),
                'firestore_doc_id': logging_result.get('doc_id') or None,
                'synced_firebase': bool(logging_result.get('synced_firebase', 0)),
                'history_id': logging_result.get('id'),
                'client_ip': logging_result.get('client_ip') or client_ip,
                'local_time': logging_result.get('local_time') or request_local_time,
                'execution_time': round(exec_time, 6),
                'source': LOG_SOURCE,
                'project_id': FIRESTORE_PROJECT_ID,
            },
        }
        return jsonify(response_body)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/decrypt/aes', methods=['POST'])
def decrypt_aes():
    try:
        data = request.get_json()
        ciphertext = data.get('ciphertext', '')
        key_b64 = data.get('key', '')

        valid, msg = validate_not_empty(ciphertext, "Ciphertext")
        if not valid:
            return jsonify({'success': False, 'error': msg}), 400
        valid, msg = validate_aes_key(key_b64)
        if not valid:
            return jsonify({'success': False, 'error': msg}), 400

        client_ip = _get_client_ip()
        request_local_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
        key = base64.b64decode(key_b64)

        _t0 = time.perf_counter()
        plaintext = AES256Cipher.decrypt(ciphertext, key)
        _t1 = time.perf_counter()
        exec_time = max(0.0, _t1 - _t0)

        logging_result = add_to_history(
            'AES-256',
            'Decrypt',
            content_length=len(plaintext),
            status='success',
            client_ip=client_ip,
            execution_time=exec_time,
            local_time_iso=request_local_time,
        )

        response_body = {
            'success': True,
            'plaintext': plaintext,
            'execution_time_ms': round(exec_time * 1000, 3),
            'logging': {
                'sqlite': bool(logging_result.get('sqlite', False)),
                'firestore': logging_result.get('firestore'),
                'firestore_doc_id': logging_result.get('doc_id') or None,
                'synced_firebase': bool(logging_result.get('synced_firebase', 0)),
                'history_id': logging_result.get('id'),
                'client_ip': logging_result.get('client_ip') or client_ip,
                'local_time': logging_result.get('local_time') or request_local_time,
                'execution_time': round(exec_time, 6),
                'source': LOG_SOURCE,
                'project_id': FIRESTORE_PROJECT_ID,
            },
        }
        return jsonify(response_body)
    except Exception as e:
        return jsonify({'success': False, 'error': 'Decryption failed. Check your key and ciphertext.'}), 400


@app.route('/api/encrypt/des', methods=['POST'])
def encrypt_des():
    try:
        data = request.get_json()
        plaintext = data.get('plaintext', '')
        key_b64 = data.get('key', '')

        valid, msg = validate_not_empty(plaintext, "Plaintext")
        if not valid:
            return jsonify({'success': False, 'error': msg}), 400
        valid, msg = validate_des_key(key_b64)
        if not valid:
            return jsonify({'success': False, 'error': msg}), 400

        client_ip = _get_client_ip()
        request_local_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
        key = base64.b64decode(key_b64)

        _t0 = time.perf_counter()
        ciphertext = DESCipher.encrypt(plaintext, key)
        _t1 = time.perf_counter()
        exec_time = max(0.0, _t1 - _t0)

        logging_result = add_to_history(
            'DES',
            'Encrypt',
            content_length=len(plaintext),
            status='success',
            client_ip=client_ip,
            execution_time=exec_time,
            local_time_iso=request_local_time,
        )

        response_body = {
            'success': True,
            'ciphertext': ciphertext,
            'execution_time_ms': round(exec_time * 1000, 3),
            'logging': {
                'sqlite': bool(logging_result.get('sqlite', False)),
                'firestore': logging_result.get('firestore'),
                'firestore_doc_id': logging_result.get('doc_id') or None,
                'synced_firebase': bool(logging_result.get('synced_firebase', 0)),
                'history_id': logging_result.get('id'),
                'client_ip': logging_result.get('client_ip') or client_ip,
                'local_time': logging_result.get('local_time') or request_local_time,
                'execution_time': round(exec_time, 6),
                'source': LOG_SOURCE,
                'project_id': FIRESTORE_PROJECT_ID,
            },
        }
        return jsonify(response_body)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/decrypt/des', methods=['POST'])
def decrypt_des():
    try:
        data = request.get_json()
        ciphertext = data.get('ciphertext', '')
        key_b64 = data.get('key', '')

        valid, msg = validate_not_empty(ciphertext, "Ciphertext")
        if not valid:
            return jsonify({'success': False, 'error': msg}), 400
        valid, msg = validate_des_key(key_b64)
        if not valid:
            return jsonify({'success': False, 'error': msg}), 400

        client_ip = _get_client_ip()
        request_local_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
        key = base64.b64decode(key_b64)

        _t0 = time.perf_counter()
        plaintext = DESCipher.decrypt(ciphertext, key)
        _t1 = time.perf_counter()
        exec_time = max(0.0, _t1 - _t0)

        logging_result = add_to_history(
            'DES',
            'Decrypt',
            content_length=len(plaintext),
            status='success',
            client_ip=client_ip,
            execution_time=exec_time,
            local_time_iso=request_local_time,
        )

        response_body = {
            'success': True,
            'plaintext': plaintext,
            'execution_time_ms': round(exec_time * 1000, 3),
            'logging': {
                'sqlite': bool(logging_result.get('sqlite', False)),
                'firestore': logging_result.get('firestore'),
                'firestore_doc_id': logging_result.get('doc_id') or None,
                'synced_firebase': bool(logging_result.get('synced_firebase', 0)),
                'history_id': logging_result.get('id'),
                'client_ip': logging_result.get('client_ip') or client_ip,
                'local_time': logging_result.get('local_time') or request_local_time,
                'execution_time': round(exec_time, 6),
                'source': LOG_SOURCE,
                'project_id': FIRESTORE_PROJECT_ID,
            },
        }
        return jsonify(response_body)
    except Exception as e:
        return jsonify({'success': False, 'error': 'Decryption failed. Check your key and ciphertext.'}), 400


@app.route('/api/encrypt/rsa', methods=['POST'])
def encrypt_rsa():
    try:
        data = request.get_json()
        plaintext = data.get('plaintext', '')
        public_key = data.get('public_key', '')

        valid, msg = validate_not_empty(plaintext, "Plaintext")
        if not valid:
            return jsonify({'success': False, 'error': msg}), 400
        valid, msg = validate_not_empty(public_key, "Public Key")
        if not valid:
            return jsonify({'success': False, 'error': msg}), 400

        client_ip = _get_client_ip()
        request_local_time = datetime.now(timezone.utc).isoformat(timespec="seconds")

        _t0 = time.perf_counter()
        ciphertext = RSACipher.encrypt(plaintext, public_key)
        _t1 = time.perf_counter()
        exec_time = max(0.0, _t1 - _t0)

        logging_result = add_to_history(
            'RSA',
            'Encrypt',
            content_length=len(plaintext),
            status='success',
            client_ip=client_ip,
            execution_time=exec_time,
            local_time_iso=request_local_time,
        )

        response_body = {
            'success': True,
            'ciphertext': ciphertext,
            'execution_time_ms': round(exec_time * 1000, 3),
            'logging': {
                'sqlite': bool(logging_result.get('sqlite', False)),
                'firestore': logging_result.get('firestore'),
                'firestore_doc_id': logging_result.get('doc_id') or None,
                'synced_firebase': bool(logging_result.get('synced_firebase', 0)),
                'history_id': logging_result.get('id'),
                'client_ip': logging_result.get('client_ip') or client_ip,
                'local_time': logging_result.get('local_time') or request_local_time,
                'execution_time': round(exec_time, 6),
                'source': LOG_SOURCE,
                'project_id': FIRESTORE_PROJECT_ID,
            },
        }
        return jsonify(response_body)
    except Exception as e:
        return jsonify({'success': False, 'error': 'Invalid public key or encryption failed'}), 400


@app.route('/api/decrypt/rsa', methods=['POST'])
def decrypt_rsa():
    try:
        data = request.get_json()
        ciphertext = data.get('ciphertext', '')
        private_key = data.get('private_key', '')

        valid, msg = validate_not_empty(ciphertext, "Ciphertext")
        if not valid:
            return jsonify({'success': False, 'error': msg}), 400
        valid, msg = validate_not_empty(private_key, "Private Key")
        if not valid:
            return jsonify({'success': False, 'error': msg}), 400

        client_ip = _get_client_ip()
        request_local_time = datetime.now(timezone.utc).isoformat(timespec="seconds")

        _t0 = time.perf_counter()
        plaintext = RSACipher.decrypt(ciphertext, private_key)
        _t1 = time.perf_counter()
        exec_time = max(0.0, _t1 - _t0)

        logging_result = add_to_history(
            'RSA',
            'Decrypt',
            content_length=len(plaintext),
            status='success',
            client_ip=client_ip,
            execution_time=exec_time,
            local_time_iso=request_local_time,
        )

        response_body = {
            'success': True,
            'plaintext': plaintext,
            'execution_time_ms': round(exec_time * 1000, 3),
            'logging': {
                'sqlite': bool(logging_result.get('sqlite', False)),
                'firestore': logging_result.get('firestore'),
                'firestore_doc_id': logging_result.get('doc_id') or None,
                'synced_firebase': bool(logging_result.get('synced_firebase', 0)),
                'history_id': logging_result.get('id'),
                'client_ip': logging_result.get('client_ip') or client_ip,
                'local_time': logging_result.get('local_time') or request_local_time,
                'execution_time': round(exec_time, 6),
                'source': LOG_SOURCE,
                'project_id': FIRESTORE_PROJECT_ID,
            },
        }
        return jsonify(response_body)
    except Exception as e:
        return jsonify({'success': False, 'error': 'Invalid private key or decryption failed'}), 400


@app.route('/api/keys/generate-aes', methods=['GET'])
def generate_aes_key():
    key = KeyGenerator.generate_aes_key()
    return jsonify({'success': True, 'key': key})


@app.route('/api/keys/generate-des', methods=['GET'])
def generate_des_key():
    key = KeyGenerator.generate_des_key()
    return jsonify({'success': True, 'key': key})


@app.route('/api/keys/generate-rsa', methods=['GET'])
def generate_rsa_pair():
    private_key, public_key = RSACipher.generate_key_pair()
    return jsonify({
        'success': True,
        'private_key': private_key,
        'public_key': public_key
    })


@app.route('/api/hash/sha256', methods=['POST'])
def hash_sha256():
    data = request.get_json()
    text = data.get('text', '')
    valid, msg = validate_not_empty(text, "Text")
    if not valid:
        return jsonify({'success': False, 'error': msg}), 400

    client_ip = _get_client_ip()
    request_local_time = datetime.now(timezone.utc).isoformat(timespec="seconds")

    _t0 = time.perf_counter()
    hash_val = HashGenerator.sha256(text)
    _t1 = time.perf_counter()
    exec_time = max(0.0, _t1 - _t0)

    logging_result = add_to_history(
        'SHA-256',
        'Hash',
        content_length=len(text),
        status='success',
        client_ip=client_ip,
        execution_time=exec_time,
        local_time_iso=request_local_time,
    )

    return jsonify({
        'success': True,
        'hash': hash_val,
        'execution_time_ms': round(exec_time * 1000, 3),
        'logging': {
            'sqlite': bool(logging_result.get('sqlite', False)),
            'firestore': logging_result.get('firestore'),
            'firestore_doc_id': logging_result.get('doc_id') or None,
            'synced_firebase': bool(logging_result.get('synced_firebase', 0)),
            'history_id': logging_result.get('id'),
            'client_ip': logging_result.get('client_ip') or client_ip,
            'local_time': logging_result.get('local_time') or request_local_time,
            'execution_time': round(exec_time, 6),
            'source': LOG_SOURCE,
            'project_id': FIRESTORE_PROJECT_ID,
        },
    })


@app.route('/api/hash/sha512', methods=['POST'])
def hash_sha512():
    data = request.get_json()
    text = data.get('text', '')
    valid, msg = validate_not_empty(text, "Text")
    if not valid:
        return jsonify({'success': False, 'error': msg}), 400

    client_ip = _get_client_ip()
    request_local_time = datetime.now(timezone.utc).isoformat(timespec="seconds")

    _t0 = time.perf_counter()
    hash_val = HashGenerator.sha512(text)
    _t1 = time.perf_counter()
    exec_time = max(0.0, _t1 - _t0)

    logging_result = add_to_history(
        'SHA-512',
        'Hash',
        content_length=len(text),
        status='success',
        client_ip=client_ip,
        execution_time=exec_time,
        local_time_iso=request_local_time,
    )

    return jsonify({
        'success': True,
        'hash': hash_val,
        'execution_time_ms': round(exec_time * 1000, 3),
        'logging': {
            'sqlite': bool(logging_result.get('sqlite', False)),
            'firestore': logging_result.get('firestore'),
            'firestore_doc_id': logging_result.get('doc_id') or None,
            'synced_firebase': bool(logging_result.get('synced_firebase', 0)),
            'history_id': logging_result.get('id'),
            'client_ip': logging_result.get('client_ip') or client_ip,
            'local_time': logging_result.get('local_time') or request_local_time,
            'execution_time': round(exec_time, 6),
            'source': LOG_SOURCE,
            'project_id': FIRESTORE_PROJECT_ID,
        },
    })


@app.route('/api/hash/md5', methods=['POST'])
def hash_md5():
    data = request.get_json()
    text = data.get('text', '')
    valid, msg = validate_not_empty(text, "Text")
    if not valid:
        return jsonify({'success': False, 'error': msg}), 400

    client_ip = _get_client_ip()
    request_local_time = datetime.now(timezone.utc).isoformat(timespec="seconds")

    _t0 = time.perf_counter()
    hash_val = HashGenerator.md5(text)
    _t1 = time.perf_counter()
    exec_time = max(0.0, _t1 - _t0)

    logging_result = add_to_history(
        'MD5',
        'Hash',
        content_length=len(text),
        status='success',
        client_ip=client_ip,
        execution_time=exec_time,
        local_time_iso=request_local_time,
    )

    return jsonify({
        'success': True,
        'hash': hash_val,
        'execution_time_ms': round(exec_time * 1000, 3),
        'logging': {
            'sqlite': bool(logging_result.get('sqlite', False)),
            'firestore': logging_result.get('firestore'),
            'firestore_doc_id': logging_result.get('doc_id') or None,
            'synced_firebase': bool(logging_result.get('synced_firebase', 0)),
            'history_id': logging_result.get('id'),
            'client_ip': logging_result.get('client_ip') or client_ip,
            'local_time': logging_result.get('local_time') or request_local_time,
            'execution_time': round(exec_time, 6),
            'source': LOG_SOURCE,
            'project_id': FIRESTORE_PROJECT_ID,
        },
    })


@app.route('/api/password/generate', methods=['GET'])
def generate_password():
    length = request.args.get('length', 16, type=int)
    password = KeyGenerator.generate_password(length)
    return jsonify({'success': True, 'password': password})


@app.route('/api/password/strength', methods=['POST'])
def check_password_strength():
    data = request.get_json()
    password = data.get('password', '')
    result = KeyGenerator.check_password_strength(password)
    return jsonify({'success': True, **result})


@app.route('/api/hash/lookup', methods=['POST'])
def hash_lookup_rainbow():
    """Educational rainbow-table hash lookup. Does NOT reverse hashes mathematically.

    Accepts JSON: { "hash": "<hex string md5|sha256|sha512>" }
    Returns:
      { success, found, algo_detected, plaintext, category, notes, rainbow_size, educational_warning }
    """
    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        data = {}
    h = (data.get("hash") or "").strip()
    if not h:
        payload = generate_educational_payload("")
        return jsonify({"success": False, "error": "No hash provided.", **payload}), 400
    payload = generate_educational_payload(h)
    return jsonify({"success": True, **payload})


@app.route('/api/hash/lookup/stats', methods=['GET'])
def hash_lookup_stats():
    """Return rainbow table sizes for dashboard UI informational display."""
    return jsonify({"success": True, "rainbow_size": total_entries()})


@app.route('/api/history/delete/<int:entry_id>', methods=['DELETE'])
def delete_history(entry_id):
    if not _current_is_admin():
        return (
            jsonify({
                'success': False,
                'error': 'FORBIDDEN: Only admin can delete audit log entries.',
            }),
            403,
        )
    ok = delete_history_entry(entry_id)
    if not ok:
        return (
            jsonify({
                'success': False,
                'error': 'Failed to delete history entry. Database unavailable.',
            }),
            503,
        )
    return jsonify({'success': True})


@app.route('/api/history/clear', methods=['DELETE'])
def clear_all_history():
    if not _current_is_admin():
        return (
            jsonify({
                'success': False,
                'error': 'FORBIDDEN: Only admin can purge the audit log.',
            }),
            403,
        )
    ok = clear_history()
    if not ok:
        return (
            jsonify({
                'success': False,
                'error': 'Failed to clear history. Database unavailable.',
            }),
            503,
        )
    return jsonify({'success': True})


@app.route('/api/admin/users', methods=['GET'])
def api_admin_list_users():
    if not _current_is_admin():
        return (
            jsonify({
                'success': False,
                'error': 'FORBIDDEN: Admin-only endpoint.',
            }),
            403,
        )
    try:
        users = list_all_users()
        return jsonify({'success': True, 'users': users})
    except Exception as exc:
        return (
            jsonify({
                'success': False,
                'error': f'User list query failed: {type(exc).__name__}',
            }),
            500,
        )


@app.after_request
def _ensure_device_cookie(resp):
    """Ensure every response carries the encryptsys_device_id cookie so user/device ownership of logs is stable."""
    try:
        existing = None
        try:
            from flask import request as _req
            existing = (_req.cookies.get("encryptsys_device_id") or "").strip()
        except Exception:
            existing = None
        if not existing:
            new_did = generate_device_id()
            resp.set_cookie(
                "encryptsys_device_id",
                new_did,
                max_age=60 * 60 * 24 * 365 * 2,
                httponly=True,
                samesite="Lax",
            )
    except Exception:
        pass
    return resp


@app.route('/api/history/export', methods=['GET'])
def export_history():
    """Export history as CSV (default) or JSON.

    Query parameters
    ----------
    format : {"csv", "json"}
        Which format to produce. Defaults to CSV.
    """
    try:
        fmt = (request.args.get("format") or "csv").lower().strip()
        history = get_history()
        if fmt == "json":
            json_data = export_history_to_json(history)
            response = make_response(json_data)
            response.headers['Content-Type'] = 'application/json'
            response.headers['Content-Disposition'] = 'attachment; filename=encryption_history.json'
            return response

        csv_data = export_history_to_csv(history)
        response = make_response(csv_data)
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=encryption_history.csv'
        return response
    except Exception as exc:
        logger.error("History export failed: %s", exc)
        return (
            jsonify({
                'success': False,
                'error': 'Failed to export history. Please try again later.',
            }),
            500,
        )


@app.route('/api/performance', methods=['POST'])
def performance_comparison():
    data = request.get_json()
    text = data.get('text', 'Hello World! This is a test string for performance comparison.')

    results = {}

    # AES performance
    aes_key = AES256Cipher.generate_key()
    start = time.time()
    aes_cipher = AES256Cipher.encrypt(text, aes_key)
    aes_encrypt_time = (time.time() - start) * 1000
    start = time.time()
    AES256Cipher.decrypt(aes_cipher, aes_key)
    aes_decrypt_time = (time.time() - start) * 1000
    results['AES-256'] = {
        'encrypt_time': round(aes_encrypt_time, 3),
        'decrypt_time': round(aes_decrypt_time, 3),
        'key_length': 256,
        'security_level': 'High',
        'speed': 'Fast'
    }

    # DES performance
    des_key = DESCipher.generate_key()
    start = time.time()
    des_cipher = DESCipher.encrypt(text, des_key)
    des_encrypt_time = (time.time() - start) * 1000
    start = time.time()
    DESCipher.decrypt(des_cipher, des_key)
    des_decrypt_time = (time.time() - start) * 1000
    results['DES'] = {
        'encrypt_time': round(des_encrypt_time, 3),
        'decrypt_time': round(des_decrypt_time, 3),
        'key_length': 56,
        'security_level': 'Very Low',
        'speed': 'Medium'
    }

    # RSA performance
    rsa_private, rsa_public = RSACipher.generate_key_pair()
    start = time.time()
    rsa_cipher = RSACipher.encrypt(text[:100], rsa_public)  # RSA is slow, use small text
    rsa_encrypt_time = (time.time() - start) * 1000
    start = time.time()
    RSACipher.decrypt(rsa_cipher, rsa_private)
    rsa_decrypt_time = (time.time() - start) * 1000
    results['RSA-2048'] = {
        'encrypt_time': round(rsa_encrypt_time, 3),
        'decrypt_time': round(rsa_decrypt_time, 3),
        'key_length': 2048,
        'security_level': 'Very High',
        'speed': 'Slow'
    }

    # Log each algorithm benchmark to history for audit trail
    add_to_history('AES-256', 'Performance Benchmark', content_length=len(text), status='success')
    add_to_history('DES',    'Performance Benchmark', content_length=len(text), status='success')
    add_to_history('RSA',    'Performance Benchmark', content_length=len(text[:100]), status='success')

    return jsonify({'success': True, 'results': results})


if __name__ == '__main__':
    import sys
    init_db()
    host = '127.0.0.1'
    port = 5000
    use_reloader = True
    i = 1
    while i < len(sys.argv):
        a = sys.argv[i]
        if a == '--host' and i + 1 < len(sys.argv):
            host = sys.argv[i + 1] ; i += 2
        elif a == '--port' and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1]) ; i += 2
        elif a == '--no-reload':
            use_reloader = False ; i += 1
        else:
            i += 1
    app.run(debug=True, host=host, port=port, use_reloader=use_reloader)
