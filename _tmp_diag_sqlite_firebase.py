"""Diagnostic: figure out exactly why (a) SQLite history is empty, and
(b) Firestore logs aren't written. Runs inside the Flask app context with
real DATABASE_PATH from Config and real firebase_config.py DB handle.

Produces PASS / FAIL for every step so you can see exactly where it dies.
"""
from __future__ import annotations

import json
import os
import sys
import time

def run() -> int:
    errors = 0
    passes = 0

    def PASS(msg):
        nonlocal passes
        passes += 1
        print(f"  [PASS #{passes:02d}] {msg}")

    def FAIL(msg, exc=None):
        nonlocal errors
        errors += 1
        print(f"  [FAIL #{errors:02d}] {msg}")
        if exc is not None:
            print(f"          EXC: {type(exc).__name__}: {exc}")

    import app as app_module

    # ------------------------------------------------------------
    # Part A: SQLite history audit
    # ------------------------------------------------------------
    db_path = app_module.app.config['DATABASE_PATH']
    print("\n--- PART A: SQLite History ---")
    print(f"  Config DATABASE_PATH = {db_path}")

    db_dir = os.path.dirname(db_path)
    print(f"  Parent dir exists?   = {os.path.isdir(db_dir)}")
    print(f"  DB file exists?      = {os.path.isfile(db_path)}")
    if os.path.isfile(db_path):
        size_kb = os.path.getsize(db_path) / 1024
        print(f"  DB file size         = {size_kb:.2f} KB")

    # Direct low-level test: bypass Flask routes
    PASS_1 = app_module.add_to_history("AES-256-DIRECT-TEST", "Encrypt")
    if PASS_1:
        PASS("add_to_history() returned True (SQLite INSERT succeeded)")
    else:
        FAIL("add_to_history() returned False — see ERROR logger output above")

    hist = app_module.get_history()
    print(f"  Rows visible to get_history() = {len(hist)}")
    if len(hist) >= 1:
        last = hist[0]
        PASS(f"Last row visible: id={last['id']} algo={last['algorithm']} op={last['operation']}")
    else:
        FAIL("Even after direct add_to_history, get_history returns 0 rows. File not being written?")

    # Try a full Flask test_client request (mimics Render)
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    app_module.app.config["TESTING"] = True
    client = app_module.app.test_client()

    key_b64 = client.get("/api/keys/generate-aes").get_json()["key"]
    enc = client.post("/api/encrypt/aes",
        data=json.dumps({"plaintext": "Firebase+SQLite end-to-end test", "key": key_b64}),
        content_type="application/json").get_json()
    if enc.get("success"):
        PASS("AES-256 encrypt via HTTP POST success=True (crypto untouched)")
    else:
        FAIL(f"AES-256 encrypt via HTTP failed: {enc}")

    rows_after_http = app_module.get_history()
    n_aes_rows = sum(1 for r in rows_after_http if r["algorithm"] == "AES-256" and r["operation"] == "Encryption")
    print(f"  AES-256 'Encryption' rows after HTTP = {n_aes_rows}")
    if n_aes_rows >= 1:
        PASS("HTTP AES encrypt properly inserted SQLite history row")
    else:
        FAIL("HTTP AES encrypt — NO SQLite row inserted (add_to_history not called / failing silently)")

    # ------------------------------------------------------------
    # Part B: Firebase Firestore audit
    # ------------------------------------------------------------
    print("\n--- PART B: Firebase Firestore ---")
    try:
        from firebase.firebase_config import db as real_db
        if real_db is None:
            FAIL("firebase.firebase_config.db IS None — import failed")
        else:
            PASS(f"Firebase Admin SDK initialized, firestore.client() = {type(real_db).__name__}")
            # Quick connection probe: read the collection to force a handshake
            try:
                probe = real_db.collection("logs").limit(1).get()
                PASS(f"Firestore handshake OK — logs collection probe returned {len(list(probe))} existing doc(s)")
            except Exception as exc:
                FAIL("Firestore handshake probe FAILED (IAM / project / quota / network)", exc)
    except Exception as exc:
        FAIL("Cannot import firebase.firebase_config.db (firebase-key.json missing or invalid)", exc)

    # Now call log_service (our real abstraction) directly
    from firebase.log_service import (
        log_encrypt, log_attack_simulation, log_password_strength,
        log_password_breach, LogContext, COLLECTION_NAME, OP_ENCRYPT,
    )
    print(f"  COLLECTION_NAME (from log_service) = '{COLLECTION_NAME}'")

    # One-shot log_encrypt
    ok = log_encrypt("AES-256-LOG-SERVICE", 42, 0.00123)
    if ok:
        PASS("log_encrypt() returned True (Firestore write success)")
    else:
        FAIL("log_encrypt() returned False — check WARNINGS from 'firebase.log_service' logger above")

    # Context manager path
    try:
        with LogContext("DES", OP_ENCRYPT, 100, test_from="trae_diagnostic") as ctx:
            time.sleep(0.01)
        PASS("LogContext __exit__ ran without propagation (no exception inside)")
    except Exception as exc:
        FAIL("LogContext with block raised (should NEVER happen — we swallow logging errors)", exc)

    # Now actually read back the two docs we just wrote to confirm Firebase persistence
    try:
        from firebase.firebase_config import db as rdb
        if rdb is not None:
            import datetime as _dt
            # Filter by our synthetic algorithm so we only see diagnostic docs
            found = 0
            for doc_ref in rdb.collection(COLLECTION_NAME).order_by("timestamp").limit(20).get():
                d = doc_ref.to_dict() or {}
                if d.get("algorithm") in ("AES-256-LOG-SERVICE", "DES") or d.get("test_from") == "trae_diagnostic":
                    found += 1
                    print(f"    + Firestore doc: algo={d.get('algorithm')} op={d.get('operation')} "
                          f"len={d.get('text_length')} t={d.get('execution_time'):.5f}s status={d.get('status')} ts={d.get('timestamp')}")
            if found >= 2:
                PASS(f"Read back {found} diagnostic documents from Firestore 'logs' collection — persistence CONFIRMED")
            else:
                FAIL(f"Read-back found only {found} diagnostic doc(s) (we just wrote 2). Writes may be silently failing.")
    except Exception as exc:
        FAIL("Firestore read-back of diagnostic docs threw an exception", exc)

    print("\n--- SUMMARY ---")
    print(f"  Passes = {passes}")
    print(f"  Fails  = {errors}")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    try:
        exit(run())
    except SystemExit:
        raise
    except Exception as e:
        print("  [CRASH] top level:", type(e).__name__, e)
        import traceback; traceback.print_exc()
        sys.exit(2)
