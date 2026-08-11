"""Centralized Firebase Firestore Logging Service.

Modular, single-source-of-truth for activity logging.
Every encryption / attack / password-related operation passes through this
module so we never duplicate logging code across the application.

Exposes two primary integration surfaces:
  1. ``LogContext``  - a context-manager that auto-measures wall-clock time
                       with ``time.perf_counter()`` and writes a ``logs`` doc
                       when the ``with`` block exits (success OR failure).
  2. ``log_operation()`` - a thin synchronous helper for call sites that
                       already measure timing or want a one-shot fire-and-forget.

Design rules (per project requirements):
  - All Firestore exceptions are caught internally -> logging MUST NEVER crash
    the caller. Encryption/hashing/attack APIs always succeed regardless of
    Firebase health.
  - We ONLY use ``logs`` collection.
  - We NEVER store plaintext secrets, keys, or ciphertexts. Only metadata.
  - Timestamps are timezone-aware UTC via ``datetime.now(timezone.utc)``.
"""
from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, Optional

try:
    from .firebase_config import db  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - defensive import guard at runtime
    db = None

logger = logging.getLogger(__name__)

COLLECTION_NAME = "encryption_history"

# ---------------------------------------------------------------------------
# Operation constants — defined here so every caller uses the same strings.
# ---------------------------------------------------------------------------
OP_ENCRYPT = "Encrypt"
OP_DECRYPT = "Decrypt"
OP_HASH = "Hash"
OP_ATTACK_SIMULATION = "Attack Simulation"
OP_PASSWORD_STRENGTH = "Password Strength Check"
OP_PASSWORD_BREACH = "Password Breach Check"
OP_PASSWORD_GENERATE = "Password Generation"
OP_KEY_GENERATE = "Key Generation"
OP_BENCHMARK = "Performance Benchmark"

STATUS_SUCCESS = "Success"
STATUS_FAILED = "Failed"


@dataclass
class LogEntry:
    """Type-safe definition of the Firestore ``logs`` document.

    Matches the schema requested in the integration spec:
    {
        "algorithm": "AES",
        "operation": "Encrypt",
        "text_length": 128,
        "execution_time": 0.0038,
        "status": "Success",
        "timestamp": "<UTC ISO timestamp>"
    }

    ``extra`` is never persisted as a top-level field — callers can attach
    optional categorization metadata (e.g. ``attack_id``, ``cracked``) that
    gets merged flat into the document when saved.
    """

    algorithm: str
    operation: str
    status: str = STATUS_SUCCESS
    text_length: int = 0
    execution_time: float = 0.0
    timestamp: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_document(self) -> Dict[str, Any]:
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        doc: Dict[str, Any] = {
            "algorithm": str(self.algorithm),
            "operation": str(self.operation),
            "status": str(self.status),
            "text_length": int(self.text_length),
            "execution_time": round(float(self.execution_time), 6),
            "timestamp": str(self.timestamp),
        }
        if isinstance(self.extra, dict):
            for k, v in self.extra.items():
                if k not in doc and v is not None:
                    try:
                        doc[k] = v
                    except Exception:
                        pass
        return doc


# ---------------------------------------------------------------------------
# Core persistence helpers (private — consumers use the public API below).
# ---------------------------------------------------------------------------
_FIRESTORE_LOCK = threading.Lock()


def _write_firestore(document: Dict[str, Any]) -> bool:
    """Best-effort Firestore write. Always returns True/False, never raises."""
    if db is None:
        logger.debug("Firebase db unavailable (not initialized) — skip log write")
        return False
    try:
        with _FIRESTORE_LOCK:
            db.collection(COLLECTION_NAME).add(document)
        return True
    except Exception as exc:
        logger.warning(
            "Firestore log write failed (silently ignored). op=%s algo=%s err=%s",
            document.get("operation"),
            document.get("algorithm"),
            exc,
        )
        return False


# ---------------------------------------------------------------------------
# Public synchronous one-shot API.
# ---------------------------------------------------------------------------
def log_operation(
    algorithm: str,
    operation: str,
    status: str = STATUS_SUCCESS,
    text_length: int = 0,
    execution_time: float = 0.0,
    timestamp: Optional[str] = None,
    **extra: Any,
) -> bool:
    """Fire-and-forget log write. Returns True if persisted, False on any issue.

    Example:
        log_operation(
            algorithm="AES-256",
            operation=OP_ENCRYPT,
            status=STATUS_SUCCESS,
            text_length=len(plaintext),
            execution_time=end - start,
        )
    """
    try:
        entry = LogEntry(
            algorithm=algorithm,
            operation=operation,
            status=status if status in (STATUS_SUCCESS, STATUS_FAILED) else STATUS_SUCCESS,
            text_length=max(0, int(text_length)),
            execution_time=max(0.0, float(execution_time)),
            timestamp=timestamp,
            extra=extra,
        )
        return _write_firestore(entry.to_document())
    except Exception as exc:
        logger.warning("log_operation() crashed (silently ignored): %s", exc)
        return False


# ---------------------------------------------------------------------------
# Context manager: measures timing + status auto-magically.
# Use this inside routes so we don't duplicate perf_counter boilerplate.
# ---------------------------------------------------------------------------
@contextmanager
def LogContext(
    algorithm: str,
    operation: str,
    text_length: int = 0,
    **extra: Any,
) -> Iterator[Dict[str, Any]]:
    """Context manager that instruments an operation block for Firestore logging.

    Features:
      - Starts a ``time.perf_counter()`` timer on entry.
      - Yields a mutable ``ctx`` dict the caller can poke:
            ctx["text_length"] = len(...)     # override size if unknown at start
            ctx["status"] = STATUS_FAILED      # mark failure without raising
            ctx["extra"].update({...})         # merge additional metadata
      - On ``__exit__``: if an exception bubbled up the block, the log is
        persisted with ``status=Failed`` (exc info captured in ``extra`` but
        the original exception still propagates so caller behavior is unchanged).
      - Firestore errors are swallowed — NEVER take down the caller.

    Typical usage inside a Flask route:

        with LogContext("AES-256", OP_ENCRYPT, len(plaintext)) as ctx:
            ciphertext = AES256Cipher.encrypt(plaintext, key)
            # if we reach here, status stays Success (default) + timing captured
        return jsonify({"success": True, "ciphertext": ciphertext})

    Failure case (caller catches but still wants a failed log):

        try:
            with LogContext("AES-256", OP_ENCRYPT, len(plaintext)) as ctx:
                result = risky_work()
        except SomeError as e:
            return jsonify({"success": False, "error": str(e)}), 400
        # ^ exception propagated through __exit__ -> Firestore records Failed.
    """
    ctx: Dict[str, Any] = {
        "algorithm": algorithm,
        "operation": operation,
        "text_length": int(text_length),
        "status": STATUS_SUCCESS,
        "start": time.perf_counter(),
        "extra": dict(extra),
    }
    exc_info: Optional[BaseException] = None
    try:
        yield ctx
    except BaseException as exc:  # noqa: BLE001 - we MUST re-raise; only record
        exc_info = exc
        ctx["status"] = STATUS_FAILED
        err_extra = ctx.setdefault("extra", {})
        if "error_type" not in err_extra:
            err_extra["error_type"] = type(exc).__name__
        if "error_message" not in err_extra:
            err_extra["error_message"] = str(exc)[:200]
        raise
    finally:
        end = time.perf_counter()
        exec_time = max(0.0, end - float(ctx.get("start", end)))
        try:
            entry = LogEntry(
                algorithm=str(ctx.get("algorithm", algorithm)),
                operation=str(ctx.get("operation", operation)),
                status=str(ctx.get("status", STATUS_SUCCESS)),
                text_length=max(0, int(ctx.get("text_length", 0))),
                execution_time=exec_time,
                timestamp=datetime.now(timezone.utc).isoformat(),
                extra=ctx.get("extra") or {},
            )
            _write_firestore(entry.to_document())
        except Exception as outer:  # pragma: no cover - absolute safety net
            logger.warning(
                "LogContext finally block failed (swallowed): %s. exc_info=%s",
                outer,
                type(exc_info).__name__ if exc_info else None,
            )


# ---------------------------------------------------------------------------
# Convenience short-hands — keep route code terse.
# ---------------------------------------------------------------------------
def log_encrypt(
    algorithm: str,
    text_length: int,
    execution_time: float,
    status: str = STATUS_SUCCESS,
    **extra: Any,
) -> bool:
    return log_operation(algorithm, OP_ENCRYPT, status, text_length, execution_time, **extra)


def log_decrypt(
    algorithm: str,
    text_length: int,
    execution_time: float,
    status: str = STATUS_SUCCESS,
    **extra: Any,
) -> bool:
    return log_operation(algorithm, OP_DECRYPT, status, text_length, execution_time, **extra)


def log_hash(
    algorithm: str,
    text_length: int,
    execution_time: float,
    status: str = STATUS_SUCCESS,
    **extra: Any,
) -> bool:
    return log_operation(algorithm, OP_HASH, status, text_length, execution_time, **extra)


def log_attack_simulation(
    attack_id: str,
    text_length: int,
    execution_time: float,
    status: str = STATUS_SUCCESS,
    **extra: Any,
) -> bool:
    return log_operation(
        attack_id, OP_ATTACK_SIMULATION, status, text_length, execution_time, **extra
    )


def log_password_strength(
    text_length: int,
    execution_time: float,
    status: str = STATUS_SUCCESS,
    **extra: Any,
) -> bool:
    return log_operation(
        "Password Checker", OP_PASSWORD_STRENGTH, status, text_length, execution_time, **extra
    )


def log_password_breach(
    text_length: int,
    execution_time: float,
    status: str = STATUS_SUCCESS,
    **extra: Any,
) -> bool:
    return log_operation(
        "Rainbow Lookup", OP_PASSWORD_BREACH, status, text_length, execution_time, **extra
    )


def log_password_generate(
    text_length: int,
    execution_time: float,
    status: str = STATUS_SUCCESS,
    **extra: Any,
) -> bool:
    return log_operation(
        "Password Generator", OP_PASSWORD_GENERATE, status, text_length, execution_time, **extra
    )
