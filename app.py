import os
import sqlite3
import time
import base64
import logging
from datetime import datetime
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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
csrf = CSRFProtect(app)

app.register_blueprint(attack_bp)

# ---------------------------------------------------------------------------
# Firebase / Firestore (optional). Only writes when configured.
# ---------------------------------------------------------------------------
try:
    from firebase.firebase_config import db as FIRESTORE_DB  # type: ignore
    if FIRESTORE_DB is None:
        logger.info("Firebase/Firestore not configured — all logs stay in local SQLite.")
except Exception as exc:  # noqa: BLE001
    FIRESTORE_DB = None
    logger.info("Firebase module import skipped (%s) — continuing with local-only history.", exc)
FIRESTORE_COLLECTION = "encryption_history"


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


def _get_client_ip() -> str:
    """Best-effort client IP for auditing (never logged to plaintext files)."""
    try:
        if request.headers.getlist("X-Forwarded-For"):
            return request.headers.getlist("X-Forwarded-For")[0].split(",")[0].strip()
        return request.remote_addr or ""
    except RuntimeError:
        return ""


def _firestore_add_history(doc_id: str, payload: dict) -> bool:
    """Firestore write — best-effort, returns True only when succeeded."""
    if FIRESTORE_DB is None:
        return False
    try:
        # firestore.client().collection(c).document(id).set(payload)
        FIRESTORE_DB.collection(FIRESTORE_COLLECTION).document(doc_id).set(payload)
        logger.info("Firestore synced entry %s/%s", payload.get("algorithm"), payload.get("operation"))
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("Firestore write failed for doc_id %s: %s", doc_id, exc)
        return False


def add_to_history(algorithm, operation, content_length: int = 0, status: str = "success"):
    """Add entry to SQLite history AND (optionally) Firebase Firestore.

    This is always best-effort. Any exception is swallowed and logged; the
    caller (encrypt/decrypt/hash APIs) continues to succeed even when the
    history layer is unavailable, so users never lose their encryption
    result due to a logging outage.

    Returns a dict with ``{sqlite: bool, firestore: bool|None, id: int|None}``
    so callers (and tests) can introspect what actually happened.
    """
    result = {"sqlite": False, "firestore": None, "id": None, "synced_firebase": 0}
    if not _ensure_db_dir():
        return result

    ts = time.time()
    client_ip = _get_client_ip()
    conn = None
    local_id = None
    doc_id = None
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        _ensure_history_table(conn)
        c = conn.cursor()
        c.execute(
            '''INSERT INTO history
               (algorithm, operation, timestamp, content_length, client_ip, status, synced_firebase, firestore_doc_id)
               VALUES (?, ?, ?, ?, ?, ?, 0, '')''',
            (algorithm, operation, ts, int(content_length or 0), client_ip, str(status or "success")),
        )
        local_id = c.lastrowid
        conn.commit()
        result["sqlite"] = True
        result["id"] = local_id
    except (sqlite3.Error, OSError) as exc:
        logger.error("SQLite history insert failed [%s/%s]: %s", algorithm, operation, exc)
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error as exc:
                logger.warning("Failed to close DB after add_to_history: %s", exc)

    # --- Firestore mirror (optional) -----------------------------------------------------
    if local_id is not None and FIRESTORE_DB is not None:
        # Stable doc id so re-runs don't create duplicates
        doc_id = f"{int(ts * 1000)}-{local_id}-{algorithm}"
        payload = {
            "local_id": local_id,
            "algorithm": algorithm,
            "operation": operation,
            "timestamp": ts,
            "timestamp_iso": datetime.fromtimestamp(ts).isoformat(timespec="seconds"),
            "content_length": int(content_length or 0),
            "client_ip_hash": "n/a",
            "status": str(status or "success"),
            "source": "text-encryption-flask-app",
        }
        synced = _firestore_add_history(doc_id, payload)
        result["firestore"] = synced
        result["synced_firebase"] = 1 if synced else 0

        # Reflect sync status back to SQLite for UI badges
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
    }


def get_history():
    """Get all history entries (newest first).

    Returns ``[]`` on any DB failure (page renders still succeed)."""
    if not _ensure_db_dir():
        return []
    conn = None
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        conn.row_factory = sqlite3.Row
        _ensure_history_table(conn)
        c = conn.cursor()
        c.execute('SELECT * FROM history ORDER BY timestamp DESC')
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

    Returns True on success (local delete succeeded). Firestore delete
    failure is logged but still returns True because the local entry is gone.
    """
    if not _ensure_db_dir():
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

    Returns True on success (local clear succeeded)."""
    if not _ensure_db_dir():
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
    return {
        "firebase_configured": FIRESTORE_DB is not None,
        "history_counts": {
            "total": total_count,
            "synced_firebase": synced_count,
            "local_only": local_count,
        },
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

        key = base64.b64decode(key_b64)
        ciphertext = AES256Cipher.encrypt(plaintext, key)
        add_to_history('AES-256', 'Encryption', content_length=len(plaintext), status='success')

        return jsonify({'success': True, 'ciphertext': ciphertext})
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

        key = base64.b64decode(key_b64)
        plaintext = AES256Cipher.decrypt(ciphertext, key)
        add_to_history('AES-256', 'Decryption', content_length=len(plaintext), status='success')

        return jsonify({'success': True, 'plaintext': plaintext})
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

        key = base64.b64decode(key_b64)
        ciphertext = DESCipher.encrypt(plaintext, key)
        add_to_history('DES', 'Encryption', content_length=len(plaintext), status='success')

        return jsonify({'success': True, 'ciphertext': ciphertext})
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

        key = base64.b64decode(key_b64)
        plaintext = DESCipher.decrypt(ciphertext, key)
        add_to_history('DES', 'Decryption', content_length=len(plaintext), status='success')

        return jsonify({'success': True, 'plaintext': plaintext})
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

        ciphertext = RSACipher.encrypt(plaintext, public_key)
        add_to_history('RSA', 'Encryption', content_length=len(plaintext), status='success')

        return jsonify({'success': True, 'ciphertext': ciphertext})
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

        plaintext = RSACipher.decrypt(ciphertext, private_key)
        add_to_history('RSA', 'Decryption', content_length=len(plaintext), status='success')

        return jsonify({'success': True, 'plaintext': plaintext})
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
    hash_val = HashGenerator.sha256(text)
    add_to_history('SHA-256', 'Hash', content_length=len(text), status='success')
    return jsonify({'success': True, 'hash': hash_val})


@app.route('/api/hash/sha512', methods=['POST'])
def hash_sha512():
    data = request.get_json()
    text = data.get('text', '')
    valid, msg = validate_not_empty(text, "Text")
    if not valid:
        return jsonify({'success': False, 'error': msg}), 400
    hash_val = HashGenerator.sha512(text)
    add_to_history('SHA-512', 'Hash', content_length=len(text), status='success')
    return jsonify({'success': True, 'hash': hash_val})


@app.route('/api/hash/md5', methods=['POST'])
def hash_md5():
    data = request.get_json()
    text = data.get('text', '')
    valid, msg = validate_not_empty(text, "Text")
    if not valid:
        return jsonify({'success': False, 'error': msg}), 400
    hash_val = HashGenerator.md5(text)
    add_to_history('MD5', 'Hash', content_length=len(text), status='success')
    return jsonify({'success': True, 'hash': hash_val})


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
    init_db()
    app.run(debug=True, port=5000)
