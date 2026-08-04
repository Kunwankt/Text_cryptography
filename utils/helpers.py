import base64
import csv
import io
import json
from datetime import datetime


def format_timestamp(timestamp):
    """Format timestamp to human-readable string"""
    if not timestamp:
        return ""
    try:
        return datetime.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError, OSError):
        return str(timestamp)


CSV_FIELDNAMES = [
    "id", "timestamp", "timestamp_iso",
    "algorithm", "operation", "status",
    "content_length",
    "synced_firebase", "firestore_doc_id",
]


def export_history_to_csv(history):
    """Export history list to CSV string.

    Includes all new metadata columns (status, content_length,
    synced_firebase, firestore_doc_id) added in the 2024 schema upgrade.
    """
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDNAMES, extrasaction="ignore")
    writer.writeheader()
    for item in history or []:
        ts = item.get("timestamp") or 0.0
        row = {
            "id": item.get("id"),
            "timestamp": format_timestamp(ts),
            "timestamp_iso": datetime.fromtimestamp(float(ts or 0)).isoformat(timespec="seconds") if ts else "",
            "algorithm": item.get("algorithm"),
            "operation": item.get("operation"),
            "status": item.get("status") or "success",
            "content_length": int(item.get("content_length") or 0),
            "synced_firebase": 1 if item.get("synced_firebase") else 0,
            "firestore_doc_id": item.get("firestore_doc_id") or "",
        }
        writer.writerow(row)
    return output.getvalue()


def export_history_to_json(history):
    """Export history list to pretty-printed JSON string.

    Includes all columns, and adds a header block (exported_at,
    total_entries) for archival traceability.
    """
    exported_at = datetime.now().astimezone().isoformat(timespec="seconds")
    entries = []
    for item in history or []:
        ts = item.get("timestamp") or 0.0
        entries.append({
            "id": item.get("id"),
            "timestamp": ts,
            "timestamp_formatted": format_timestamp(ts),
            "algorithm": item.get("algorithm"),
            "operation": item.get("operation"),
            "status": item.get("status") or "success",
            "content_length": int(item.get("content_length") or 0),
            "client_ip_present": bool(item.get("client_ip")),
            "synced_firebase": bool(item.get("synced_firebase")),
            "firestore_doc_id": item.get("firestore_doc_id") or None,
        })
    payload = {
        "exported_at": exported_at,
        "source": "Multi Algorithm Text Encryption System",
        "schema_version": 2,
        "total_entries": len(entries),
        "entries": entries,
    }
    return json.dumps(payload, indent=2, sort_keys=False)
