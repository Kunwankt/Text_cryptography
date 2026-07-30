"""Attack Simulator blueprint.

Completely separate module — registers its own page route and JSON APIs.
Does not import, modify, or call any of the existing app routes.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime
from typing import Dict

from flask import Blueprint, jsonify, render_template, request, Response, make_response

from utils.attack_sim import (
    ATTACK_TYPES,
    estimate_entropy_bits,
    evaluate_password,
    get_attack_types_public,
    parse_hints,
    simulate_attack,
)

logger = logging.getLogger(__name__)

attack_bp = Blueprint(
    "attack_simulator",
    __name__,
    template_folder="../templates",
    static_folder="../static",
)

_STATS_LOCK = threading.Lock()
_STATS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "database",
    "attack_stats.json",
)

DEFAULT_STATS: Dict = {
    "total_simulations": 0,
    "strong_passwords_tested": 0,
    "weak_passwords_tested": 0,
    "total_score_sum": 0,
    "per_attack_count": {k: 0 for k in ATTACK_TYPES.keys()},
}


def _ensure_stats_dir() -> None:
    d = os.path.dirname(_STATS_FILE)
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass


def _load_stats() -> Dict:
    _ensure_stats_dir()
    if not os.path.isfile(_STATS_FILE):
        return dict(DEFAULT_STATS)
    try:
        with open(_STATS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to load attack stats: %s", exc)
        return dict(DEFAULT_STATS)

    merged = dict(DEFAULT_STATS)
    merged.update(data)
    for k in ATTACK_TYPES.keys():
        merged["per_attack_count"].setdefault(k, 0)
    return merged


def _save_stats(stats: Dict) -> None:
    _ensure_stats_dir()
    try:
        with open(_STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)
    except OSError as exc:
        logger.warning("Failed to persist attack stats: %s", exc)


def _record_statistics(attack_id: str, score: int) -> Dict:
    with _STATS_LOCK:
        stats = _load_stats()
        stats["total_simulations"] = int(stats.get("total_simulations", 0)) + 1
        stats["total_score_sum"] = int(stats.get("total_score_sum", 0)) + int(score)
        if score >= 70:
            stats["strong_passwords_tested"] = int(stats.get("strong_passwords_tested", 0)) + 1
        if score < 50:
            stats["weak_passwords_tested"] = int(stats.get("weak_passwords_tested", 0)) + 1
        pac = stats.setdefault("per_attack_count", {})
        pac[attack_id] = int(pac.get(attack_id, 0)) + 1
        _save_stats(stats)
        return dict(stats)


@attack_bp.route("/attack-simulator")
def attack_simulator_page():
    attack_types = get_attack_types_public()
    return render_template(
        "attack_simulator.html",
        attack_types=attack_types,
        initial_stats=get_public_stats(),
    )


@attack_bp.route("/api/attack/types", methods=["GET"])
def api_attack_types():
    return jsonify({"success": True, "types": get_attack_types_public()})


@attack_bp.route("/api/attack/simulate", methods=["POST"])
def api_simulate():
    data = request.get_json(silent=True) or {}
    attack_id = (data.get("attack") or "").strip().lower()
    password = data.get("password") or ""
    password = str(password)
    raw_hints = data.get("hints")
    # Hints can be sent as:
    #   - string: "Rohit, 15/08/1995, Delhi"
    #   - list of strings: ["Rohit", "15/08/1995", "Delhi"]
    #   - omitted / null → treated as empty (generic wordlist)
    normalized_hints: str = ""
    if isinstance(raw_hints, str):
        normalized_hints = raw_hints
    elif isinstance(raw_hints, list):
        normalized_hints = ", ".join(str(h).strip() for h in raw_hints if str(h).strip())
    # Server-side cap on total hint length to prevent pathological inputs.
    if len(normalized_hints) > 1200:
        normalized_hints = normalized_hints[:1200]

    if attack_id not in ATTACK_TYPES:
        return jsonify({"success": False, "error": "Unknown attack type."}), 400
    if not password:
        return jsonify({"success": False, "error": "Password is required."}), 400
    if len(password) > 128:
        return jsonify({"success": False, "error": "Password too long (max 128 chars)."}), 400

    try:
        result = simulate_attack(attack_id, password, hints=normalized_hints or None)
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Attack simulation failed")
        return jsonify({"success": False, "error": f"Simulation error: {exc}"}), 500

    public = result.to_public_dict()
    _, breakdown, _ = evaluate_password(password)
    public["score"] = int(result.score)
    public["security_breakdown"] = breakdown
    public["entropy_bits"] = estimate_entropy_bits(password)
    public["server_timestamp"] = int(time.time())
    # Echo back the parsed hints so the UI can show them in the report.
    parsed_hints = parse_hints(normalized_hints)
    public["hints_used"] = parsed_hints

    stats = _record_statistics(attack_id, result.score)
    public["stats"] = _public_view_stats(stats)
    return jsonify({"success": True, "result": public})


def _public_view_stats(stats: Dict) -> Dict:
    total = int(stats.get("total_simulations", 0))
    score_sum = int(stats.get("total_score_sum", 0))
    avg = round(score_sum / total, 1) if total > 0 else 0.0
    return {
        "total_simulations": total,
        "strong_passwords_tested": int(stats.get("strong_passwords_tested", 0)),
        "weak_passwords_tested": int(stats.get("weak_passwords_tested", 0)),
        "average_security_score": avg,
        "per_attack_count": dict(stats.get("per_attack_count", {})),
    }


def get_public_stats() -> Dict:
    with _STATS_LOCK:
        return _public_view_stats(_load_stats())


@attack_bp.route("/api/attack/statistics", methods=["GET"])
def api_statistics():
    return jsonify({"success": True, "statistics": get_public_stats()})


def _build_report_text(result_public: Dict, password: str, hints_used: list) -> str:
    """Build a human-readable plain-text report for download."""
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("         ATTACK SIMULATION REPORT — Multi Algorithm Text Encryption System")
    lines.append("=" * 72)
    lines.append("Generated : " + datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    lines.append("")

    lines.append("-" * 72)
    lines.append("  ATTACK SUMMARY")
    lines.append("-" * 72)
    lines.append(f"  Attack Type            : {result_public.get('attack', '—')}")
    lines.append(f"  Password (masked)      : {'*' * len(password)} ({len(password)} chars)")
    lines.append(f"  Security Score         : {result_public.get('score', 0)} / 100")
    lines.append(f"  Password Strength      : {result_public.get('strength', '—')}")
    lines.append(f"  Risk Level             : {result_public.get('risk', '—')}")
    lines.append(f"  Estimated Crack Time   : {result_public.get('estimated_time', '—')}")
    lines.append(f"  Attack Success Rate    : {result_public.get('success_rate', '—')}")
    lines.append(f"  Total Tries (approx)   : {result_public.get('attempts_formatted', '—')}")
    lines.append(f"  Entropy                : {result_public.get('entropy_bits', 0)} bits")
    if hints_used:
        lines.append(f"  Personalized Hints     : {len(hints_used)} hint(s) loaded")
        for i, h in enumerate(hints_used, 1):
            lines.append(f"    [{i}] {h}")
    lines.append("")

    lines.append("-" * 72)
    lines.append("  CATEGORY-BY-CATEGORY ATTACK REPORT (10,000,000,000 candidates each)")
    lines.append("-" * 72)
    attack_report = result_public.get("attack_report") or []
    total_hit = 0
    total_skipped = 0
    for idx, cat in enumerate(attack_report, 1):
        if cat.get("skipped"):
            status = "⏭  SKIPPED (early exit)"
            total_skipped += 1
        elif cat.get("hit"):
            status = "✅ MATCH FOUND"
            total_hit += 1
        else:
            status = "❌ No match"
        lines.append(f"")
        lines.append(f"  [{cat.get('priority', idx)}] {cat.get('category_name', 'Category')}")
        lines.append(f"       Category ID   : {cat.get('category_id', '—')}")
        if cat.get("skipped"):
            lines.append(f"       Attempts      : SKIPPED (0 scanned — early exit)")
        else:
            lines.append(f"       Attempts      : {cat.get('attempts_formatted', '—')} ({cat.get('attempts', 0):,})")
        lines.append(f"       Status        : {status}")
        if cat.get("hit") and cat.get("hit_position"):
            lines.append(f"       Found at #    : {cat['hit_position']:,}")
        if cat.get("skipped") and cat.get("skip_reason"):
            lines.append(f"       Skip reason   : {cat['skip_reason']}")
        if cat.get("hit_candidate"):
            cand = cat["hit_candidate"]
            masked = cand[:2] + "*" * max(0, len(cand) - 4) + (cand[-2:] if len(cand) >= 4 else "")
            lines.append(f"       Match (masked): {masked}")
        lines.append(f"       Description   : {cat.get('description', '—')}")
    lines.append("")
    lines.append(f"  Total Categories Scanned : {len(attack_report)}")
    lines.append(f"  Categories With A Match  : {total_hit}")
    if result_public.get("early_exited"):
        lines.append(f"  ⏭  EARLY EXIT            : YES — remaining {result_public.get('skip_count', 0)} categories skipped automatically")
        if result_public.get("first_hit_category_name"):
            lines.append(f"  First match in category  : Priority #{result_public.get('first_hit_priority', '?')} — {result_public['first_hit_category_name']}")
    elif total_skipped:
        lines.append(f"  Categories Skipped       : {total_skipped}")
    total_candidates = sum(c.get("attempts", 0) for c in attack_report)
    lines.append(f"  Total Candidates Tried   : {total_candidates:,} ({result_public.get('total_report_attempts_formatted', '—')})")
    lines.append("")

    lines.append("-" * 72)
    lines.append("  SECURITY BREAKDOWN")
    lines.append("-" * 72)
    bd = result_public.get("security_breakdown") or {}
    lines.append(f"    Length Score         : {bd.get('length', 0)} / 40")
    lines.append(f"    Variety Score        : {bd.get('variety', 0)} / 45")
    lines.append(f"    Randomness Score     : {bd.get('randomness', 0)} / 35")
    lines.append("")

    lines.append("-" * 72)
    lines.append("  RECOMMENDED IMPROVEMENTS")
    lines.append("-" * 72)
    tips = result_public.get("tips") or []
    if tips:
        for i, t in enumerate(tips, 1):
            lines.append(f"  {i}. {t}")
    else:
        lines.append("  ✅ No specific improvements detected.")
    lines.append("")

    lines.append("-" * 72)
    lines.append("  EDUCATIONAL NOTES")
    lines.append("-" * 72)
    edu = result_public.get("educational") or {}
    if edu.get("why_works"):
        lines.append(f"  Why this attack works :")
        lines.append(f"    {edu['why_works']}")
    if edu.get("why_fails"):
        lines.append(f"  Why weak passwords fail :")
        lines.append(f"    {edu['why_fails']}")
    if edu.get("defend"):
        lines.append(f"  How to defend :")
        lines.append(f"    {edu['defend']}")
    if edu.get("best_practices"):
        lines.append(f"  Best practices :")
        for bp in edu["best_practices"].split("\n"):
            lines.append(f"    {bp}")
    lines.append("")
    lines.append("=" * 72)
    lines.append("  END OF REPORT — Educational simulation only. No real cracking performed.")
    lines.append("=" * 72)
    return "\n".join(lines)


@attack_bp.route("/api/attack/report/download", methods=["POST"])
def api_download_report():
    """Generate and return an attack report as downloadable JSON or TXT.

    Accepts the same payload as /api/attack/simulate plus an extra
    `format` field ("json" or "txt", default "txt").
    """
    data = request.get_json(silent=True) or {}
    attack_id = (data.get("attack") or "").strip().lower()
    password = str(data.get("password") or "")
    fmt = (data.get("format") or "txt").strip().lower()
    if fmt not in ("json", "txt"):
        fmt = "txt"

    raw_hints = data.get("hints")
    normalized_hints: str = ""
    if isinstance(raw_hints, str):
        normalized_hints = raw_hints
    elif isinstance(raw_hints, list):
        normalized_hints = ", ".join(str(h).strip() for h in raw_hints if str(h).strip())
    if len(normalized_hints) > 1200:
        normalized_hints = normalized_hints[:1200]

    if attack_id not in ATTACK_TYPES:
        return jsonify({"success": False, "error": "Unknown attack type."}), 400
    if not password:
        return jsonify({"success": False, "error": "Password is required."}), 400
    if len(password) > 128:
        return jsonify({"success": False, "error": "Password too long (max 128 chars)."}), 400

    try:
        result = simulate_attack(attack_id, password, hints=normalized_hints or None)
    except Exception as exc:
        logger.exception("Attack simulation failed for download")
        return jsonify({"success": False, "error": f"Simulation error: {exc}"}), 500

    public = result.to_public_dict()
    _, breakdown, _ = evaluate_password(password)
    public["score"] = int(result.score)
    public["security_breakdown"] = breakdown
    public["entropy_bits"] = estimate_entropy_bits(password)
    public["server_timestamp"] = int(time.time())
    parsed_hints = parse_hints(normalized_hints)
    public["hints_used"] = parsed_hints

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_attack = "".join(c if c.isalnum() or c in "-_" else "_" for c in attack_id)

    if fmt == "json":
        payload = json.dumps({
            "report_type": "attack_simulation_report",
            "generated_at": datetime.now().isoformat() + "Z",
            "password_length": len(password),
            "result": public,
        }, indent=2, ensure_ascii=False)
        filename = f"attack_report_{safe_attack}_{timestamp}.json"
        resp = make_response(payload)
        resp.headers["Content-Type"] = "application/json; charset=utf-8"
        resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return resp

    # TXT (default)
    txt = _build_report_text(public, password, parsed_hints)
    filename = f"attack_report_{safe_attack}_{timestamp}.txt"
    resp = make_response(txt)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp
