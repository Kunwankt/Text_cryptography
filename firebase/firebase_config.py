"""Firebase Admin SDK + Firestore bootstrap.

Supports 3 ways to provide a service-account credential, in priority order:

1. Environment variable ``FIREBASE_SERVICE_ACCOUNT_JSON`` — an inline JSON
   string containing the full service account payload. This is the RECOMMENDED
   way for Render / Heroku / PaaS deployments that only offer environment
   secrets (not file uploads). We dump it to a temp file and hand that path
   to the SDK.

2. Environment variable ``GOOGLE_APPLICATION_CREDENTIALS`` — absolute path to
   a service-account JSON file on disk. This is the Google ADC default and is
   used by both local Firebase emulators and cloud shell environments.

3. On-disk ``firebase-key.json`` inside the project root (the original pattern).
   Kept as a fallback so developer laptops continue to work with their existing
   checkout.

The ``db = firestore.client()`` handle is placed at module scope. Import errors
are caught and converted to a ``db = None`` sentinel ONLY by ``log_service.py``.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_INIT_LOCK = threading.Lock()

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_service_account_info() -> Optional[dict]:
    """Return parsed service-account dict or None if no creds were provided."""
    raw_env = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
    if raw_env:
        try:
            info = json.loads(raw_env)
            if isinstance(info, dict) and info.get("type") == "service_account":
                logger.info(
                    "Firebase credentials loaded from FIREBASE_SERVICE_ACCOUNT_JSON "
                    "env var (project_id=%s)", info.get("project_id")
                )
                return info
            logger.warning(
                "FIREBASE_SERVICE_ACCOUNT_JSON present but not a valid service "
                "account JSON (expect type=service_account). Falling through."
            )
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning(
                "FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON (%s). Falling "
                "through to file-based credentials.", exc
            )

    gac = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
    candidates = []
    if gac:
        candidates.append(Path(gac))
    candidates.append(BASE_DIR / "firebase-key.json")
    for candidate in candidates:
        if candidate.is_file():
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    info = json.load(f)
                if isinstance(info, dict) and info.get("type") == "service_account":
                    logger.info(
                        "Firebase credentials loaded from file %s (project_id=%s)",
                        candidate, info.get("project_id"),
                    )
                    return info
                logger.warning(
                    "File %s exists but does not contain a valid Firebase "
                    "service-account JSON. Skipping.", candidate
                )
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to read %s: %s", candidate, exc)
    return None


def _build_credential():
    """Return (credential, project_id, firebase_app_options_dict) or None-tuple."""
    try:
        import firebase_admin  # noqa: WPS433
        from firebase_admin import credentials  # noqa: WPS433
    except ImportError:
        logger.warning(
            "firebase_admin package is not installed in this environment. "
            "Install it via `pip install firebase-admin` or add it to "
            "requirements.txt. All Firestore logging will be silently skipped."
        )
        return None, None, None

    info = _load_service_account_info()
    if info is None:
        logger.warning(
            "No Firebase service-account credentials could be located (checked "
            "FIREBASE_SERVICE_ACCOUNT_JSON, GOOGLE_APPLICATION_CREDENTIALS, and "
            "<project>/firebase-key.json). All Firestore logging will be skipped."
        )
        return None, None, None

    project_id = info.get("project_id")

    try:
        cred = credentials.Certificate(info)
    except (ValueError, KeyError, TypeError) as exc:
        logger.warning("Could not construct Firebase Certificate from info: %s", exc)
        return None, None, None

    options = {}
    if project_id:
        options["projectId"] = project_id
    # storageBucket + databaseURL are optional; Firestore just needs project.
    default_bucket = os.environ.get("FIREBASE_STORAGE_BUCKET") or info.get(
        "storageBucket"
    )
    if default_bucket:
        options["storageBucket"] = default_bucket
    default_db_url = os.environ.get("FIREBASE_DATABASE_URL") or info.get(
        "databaseURL"
    )
    if default_db_url:
        options["databaseURL"] = default_db_url

    return cred, project_id, options


_cred, _project, _options = _build_credential()
_app = None
db = None
project_id: Optional[str] = _project

if _cred is not None:
    try:
        import firebase_admin  # noqa: WPS433
        from firebase_admin import firestore  # noqa: WPS433

        with _INIT_LOCK:
            if not firebase_admin._apps:
                _app = firebase_admin.initialize_app(_cred, _options or None)
            else:
                # Some test harnesses may pre-init an app; grab the default
                _app = firebase_admin.get_app()
        db = firestore.client(_app)
        logger.info(
            "Firestore client initialized (project=%s, app_name=%s)",
            _project or "<from-cert>", getattr(_app, "name", "default"),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Firebase/Firestore failed to initialize (continuing without it): %s",
            exc,
        )
        db = None
else:
    # _load_service_account_info() already logged the missing-credential warning
    pass
