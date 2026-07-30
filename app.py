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
from utils.helpers import export_history_to_csv
from routes.attack_routes import attack_bp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
csrf = CSRFProtect(app)

app.register_blueprint(attack_bp)


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


def add_to_history(algorithm, operation):
    """Add entry to history. This is a best-effort operation — DB errors are logged
    and never propagated so that encryption/hash APIs still succeed when history is
    unavailable.
    """
    if not _ensure_db_dir():
        return False
    conn = None
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        c = conn.cursor()
        c.execute(
            'INSERT INTO history (algorithm, operation, timestamp) VALUES (?, ?, ?)',
            (algorithm, operation, time.time()),
        )
        conn.commit()
        return True
    except (sqlite3.Error, OSError) as exc:
        logger.error(
            "Failed to record history [%s/%s: %s",
            algorithm, operation, exc,
        )
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error as exc:
                logger.warning(
                    "Failed to close DB connection after add_to_history: %s",
                    exc,
                )


def get_history():
    """Get all history entries. Returns an empty list and logs an error on failure
    rather than raising, so page renders never crash due to a DB outage.
    """
    if not _ensure_db_dir():
        return []
    conn = None
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        c = conn.cursor()
        c.execute('SELECT * FROM history ORDER BY timestamp DESC')
        rows = c.fetchall()
        history = []
        for row in rows:
            history.append({
                'id': row[0],
                'algorithm': row[1],
                'operation': row[2],
                'timestamp': row[3],
            })
        return history
    except (sqlite3.Error, OSError) as exc:
        logger.error("Failed to load history from DB: %s", exc)
        return []
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error as exc:
                logger.warning(
                    "Failed to close DB connection after get_history: %s", exc
                )


def delete_history_entry(entry_id):
    """Delete a history entry. Returns True on success, False on failure."""
    if not _ensure_db_dir():
        return False
    conn = None
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        c = conn.cursor()
        c.execute('DELETE FROM history WHERE id = ?', (entry_id,))
        conn.commit()
        return True
    except (sqlite3.Error, OSError) as exc:
        logger.error("Failed to delete history entry %s: %s", entry_id, exc)
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error as exc:
                logger.warning(
                    "Failed to close DB connection after delete_history_entry: %s",
                    exc,
                )


def clear_history():
    """Clear all history entries. Returns True on success, False on failure."""
    if not _ensure_db_dir():
        return False
    conn = None
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        c = conn.cursor()
        c.execute('DELETE FROM history')
        conn.commit()
        return True
    except (sqlite3.Error, OSError) as exc:
        logger.error("Failed to clear history: %s", exc)
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error as exc:
                logger.warning(
                    "Failed to close DB connection after clear_history: %s", exc
                )


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/google8f0ce872da7fe93a.html')
def google_site_verification():
    return send_from_directory(app.root_path, 'google8f0ce872da7fe93a.html')


@app.route('/dashboard')
def dashboard():
    history = get_history()
    return render_template('dashboard.html', history=history)


@app.route('/encrypt')
def encrypt_page():
    return render_template('encrypt.html')


@app.route('/decrypt')
def decrypt_page():
    return render_template('decrypt.html')


@app.route('/history')
def history_page():
    history = get_history()
    return render_template('history.html', history=history)


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
        add_to_history('AES-256', 'Encryption')

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
        add_to_history('AES-256', 'Decryption')

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
        add_to_history('DES', 'Encryption')

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
        add_to_history('DES', 'Decryption')

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
        add_to_history('RSA', 'Encryption')

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
        add_to_history('RSA', 'Decryption')

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
    add_to_history('SHA-256', 'Hash')
    return jsonify({'success': True, 'hash': hash_val})


@app.route('/api/hash/sha512', methods=['POST'])
def hash_sha512():
    data = request.get_json()
    text = data.get('text', '')
    valid, msg = validate_not_empty(text, "Text")
    if not valid:
        return jsonify({'success': False, 'error': msg}), 400
    hash_val = HashGenerator.sha512(text)
    add_to_history('SHA-512', 'Hash')
    return jsonify({'success': True, 'hash': hash_val})


@app.route('/api/hash/md5', methods=['POST'])
def hash_md5():
    data = request.get_json()
    text = data.get('text', '')
    valid, msg = validate_not_empty(text, "Text")
    if not valid:
        return jsonify({'success': False, 'error': msg}), 400
    hash_val = HashGenerator.md5(text)
    add_to_history('MD5', 'Hash')
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
    try:
        history = get_history()
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

    return jsonify({'success': True, 'results': results})


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
