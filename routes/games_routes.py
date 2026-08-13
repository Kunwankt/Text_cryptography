"""Cryptography Games Blueprint — /games, /api/games/*

Completely standalone module. Reuses:
- Base template (navbar, footer, glassmorphism theme)
- Existing CSRF via base.html's meta tag
- JSON-file statistics storage (parallel to routes/attack_routes.py)
"""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Tuple

from flask import Blueprint, jsonify, render_template, request

from utils.crypto_games import (
    GAME_CATALOG,
    RANKS,
    generate_brute_force_challenge,
    generate_cipher_puzzle,
    generate_crack_the_cipher_level,
    generate_crazy_mode_level,
    generate_daily_cipher,
    generate_encryption_race_level,
    generate_guess_the_cipher_level,
    generate_hash_detective_level,
    generate_key_guessing_level,
    pick_vulnerability,
    rank_for_xp,
)

try:
    from firebase.user_service import (
        current_session_user,
        update_game_progress,
        record_device_id,
    )
    _USER_SERVICE_AVAILABLE = True
except Exception:  # pragma: no cover
    _USER_SERVICE_AVAILABLE = False

try:
    from flask import session as flask_session
except Exception:  # pragma: no cover
    flask_session = None

LOG = logging.getLogger(__name__)

bp = Blueprint("games", __name__, url_prefix="")

_STATS_DIR = Path(os.environ.get("DATA_DIR", Path(__file__).resolve().parent.parent))
STATS_FILE = _STATS_DIR / "games_stats.json"
_stats_lock = threading.Lock()


def _broken_streak_check(stats: Dict[str, Any]) -> Dict[str, Any]:
    """If last daily solve was NOT yesterday and NOT today, reset streak to 0.

    Caller is responsible for persisting the returned (possibly mutated) stats.
    """
    import datetime as _dt
    try:
        last_date_str = stats.get("last_daily_complete_date")
        if not last_date_str:
            return stats
        if not isinstance(last_date_str, str):
            return stats
        today = _dt.date.today()
        yesterday = today - _dt.timedelta(days=1)
        try:
            last = _dt.date.fromisoformat(last_date_str)
        except (ValueError, TypeError):
            return stats
        if last != today and last != yesterday:
            stats["daily_streak"] = 0
    except Exception:
        pass
    return stats


def _load_stats() -> Dict[str, Any]:
    with _stats_lock:
        if not STATS_FILE.exists():
            stats = {
                "total_games_played": 0,
                "total_xp_earned": 0,
                "daily_streak": 0,
                "last_daily_complete_date": None,
                "best_scores": {},
                "wins": {},
                "games_finished": {},
            }
            try:
                STATS_FILE.write_text(json.dumps(stats, indent=2), encoding="utf-8")
            except OSError as exc:
                LOG.warning("Could not write games stats file: %s", exc)
            return stats
        try:
            data = json.loads(STATS_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            LOG.warning("Corrupt games stats file, starting fresh: %s", exc)
            return {
                "total_games_played": 0,
                "total_xp_earned": 0,
                "daily_streak": 0,
                "last_daily_complete_date": None,
                "best_scores": {},
                "wins": {},
                "games_finished": {},
            }
        for key in ("best_scores", "wins", "games_finished"):
            data.setdefault(key, {})
        dirty = False
        if data.get("daily_streak", 0) > 0:
            before_streak = int(data.get("daily_streak", 0))
            data = _broken_streak_check(data)
            if int(data.get("daily_streak", 0)) != before_streak:
                dirty = True
        if dirty:
            try:
                STATS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
            except OSError as exc:
                LOG.warning("Could not persist broken-streak fix to stats file: %s", exc)
        return data


def _save_stats(stats: Dict[str, Any]) -> None:
    with _stats_lock:
        try:
            STATS_FILE.write_text(json.dumps(stats, indent=2), encoding="utf-8")
        except OSError as exc:
            LOG.warning("Could not persist games stats: %s", exc)


def _build_leaderboard(limit: int = 20) -> List[Dict[str, Any]]:
    """Build a PUBLIC leaderboard — merge Firebase users + local device player.

    Always returns a list — no auth required. All values are native JSON-safe types.
    """
    rows: List[Dict[str, Any]] = []
    # 1) Pull from Firebase if available
    if _USER_SERVICE_AVAILABLE:
        try:
            try:
                from firebase.user_service import list_users_for_leaderboard
                fb_rows: Any = list_users_for_leaderboard(limit=max(3, int(limit)))
            except Exception:
                fb_rows = []
            if fb_rows and isinstance(fb_rows, list):
                for r in fb_rows:
                    try:
                        if not isinstance(r, dict):
                            continue
                        bs = r.get("best_scores") or {}
                        if not isinstance(bs, dict):
                            bs = {}
                        cm_best = int(bs.get("crazy_mode_best") or bs.get("crazy_mode") or 0)
                        xp_row = int(r.get("xp") or r.get("total_xp") or 0)
                        wins_row = int(r.get("wins") or r.get("total_wins") or 0)
                        streak_row = int(r.get("streak") or r.get("daily_streak") or 0)
                        rank_name = r.get("rank")
                        if not rank_name or not isinstance(rank_name, str):
                            try:
                                r_calc = rank_for_xp(xp_row) or {}
                                rank_name = str(r_calc.get("name") or "Novice")
                            except Exception:
                                rank_name = "Novice"
                        disp = r.get("display_name") or r.get("username") or "Anonymous"
                        rows.append({
                            "display_name": str(disp),
                            "username": str(r.get("username") or ""),
                            "is_admin": bool(r.get("is_admin")),
                            "xp": xp_row,
                            "wins": wins_row,
                            "streak": streak_row,
                            "crazy_best": cm_best,
                            "rank": str(rank_name),
                            "source": "firebase",
                        })
                    except Exception:
                        continue
        except Exception:
            pass
    # 2) Local device stats (shown as THIS DEVICE row, highlighted separately)
    try:
        stats_local = _load_stats()
        xp_local = int(stats_local.get("total_xp_earned", 0))
        wins_local = sum(int(v) for v in stats_local.get("wins", {}).values())
        bs_local = stats_local.get("best_scores") or {}
        if not isinstance(bs_local, dict):
            bs_local = {}
        cm_local = int(bs_local.get("crazy_mode_best") or bs_local.get("crazy_mode") or 0)
        streak_local = int(stats_local.get("daily_streak", 0))
        if xp_local > 0 or wins_local > 0 or cm_local > 0 or streak_local > 0:
            try:
                r_calc = rank_for_xp(xp_local) or {}
                rn_local = str(r_calc.get("name") or "Novice")
            except Exception:
                rn_local = "Novice"
            rows.append({
                "display_name": "You",
                "username": "",
                "is_admin": False,
                "xp": xp_local,
                "wins": int(wins_local),
                "streak": streak_local,
                "crazy_best": cm_local,
                "rank": rn_local,
                "source": "local",
            })
    except Exception:
        pass
    # 3) Sort by XP desc, streak as tiebreaker; take top N
    try:
        rows.sort(key=lambda r: (-int(r.get("xp") or 0), -int(r.get("streak") or 0)))
    except Exception:
        pass
    safe_n = max(1, min(int(limit or 20), 100))
    return rows[:safe_n]


@bp.route("/games")
def games_home():
    stats = _load_stats()
    xp = int(stats.get("total_xp_earned", 0))
    rank = rank_for_xp(xp)
    total_games = int(stats.get("total_games_played", 0))
    wins_total = sum(int(v) for v in stats.get("wins", {}).values())
    completed_total = sum(int(v) for v in stats.get("games_finished", {}).values())
    average_xp_per_game = (xp / total_games) if total_games else 0
    leaderboard = _build_leaderboard(limit=20)
    return render_template(
        "games.html",
        games=GAME_CATALOG,
        stats={
            "total_games_played": total_games,
            "total_xp_earned": xp,
            "wins_total": wins_total,
            "completed_total": completed_total,
            "average_xp_per_game": round(average_xp_per_game, 1),
            "daily_streak": int(stats.get("daily_streak", 0)),
        },
        rank=rank,
        ranks=RANKS,
        daily=generate_daily_cipher(),
        leaderboard=leaderboard,
    )


@bp.get("/api/games/types")
def api_games_types():
    return jsonify({"success": True, "games": list(GAME_CATALOG)})


def _difficulty_param() -> str:
    d = (request.args.get("difficulty") or "easy").lower()
    return d if d in ("easy", "medium", "hard") else "easy"


def _seed_param() -> int | None:
    raw = request.args.get("seed", type=str)
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


@bp.get("/api/games/level/<game_id>")
def api_games_level(game_id: str):
    difficulty = _difficulty_param()
    seed = _seed_param()
    try:
        if game_id == "crack_cipher":
            level = generate_crack_the_cipher_level(difficulty, seed)
        elif game_id == "guess_cipher":
            level = generate_guess_the_cipher_level(difficulty, seed)
        elif game_id == "brute_force":
            level = generate_brute_force_challenge(difficulty, seed)
        elif game_id == "cipher_puzzle":
            level = generate_cipher_puzzle(difficulty, seed)
        elif game_id == "key_guessing":
            level = generate_key_guessing_level(difficulty, seed)
        elif game_id == "hash_detective":
            level = generate_hash_detective_level(difficulty, seed)
        elif game_id == "encryption_race":
            level = generate_encryption_race_level(seed)
        elif game_id == "find_vulnerability":
            level = pick_vulnerability(seed)
        elif game_id == "daily_cipher":
            level = generate_daily_cipher()
        elif game_id == "crazy_mode":
            qidx = request.args.get("q", 0, type=int) or 0
            total = request.args.get("total", 5, type=int) or 5
            total = max(3, min(total, 25))
            level = generate_crazy_mode_level(seed=seed, question_index=qidx, total_questions=total)
        else:
            return jsonify({"success": False, "error": f"Unknown game_id: {game_id!r}"}), 404
    except Exception as exc:  # pragma: no cover - defensive
        LOG.exception("Level generator failed for %s: %s", game_id, exc)
        return jsonify({"success": False, "error": "Level generator failed"}), 500
    return jsonify({"success": True, "game_id": game_id, "level": level})


@bp.get("/api/games/statistics")
def api_games_statistics():
    stats = _load_stats()
    xp = int(stats.get("total_xp_earned", 0))
    rank = rank_for_xp(xp)
    wins_total = sum(int(v) for v in stats.get("wins", {}).values())
    completed_total = sum(int(v) for v in stats.get("games_finished", {}).values())
    accuracy = (
        round(100.0 * wins_total / completed_total, 1) if completed_total > 0 else 0
    )
    return jsonify({
        "success": True,
        "statistics": {
            "total_games_played": int(stats.get("total_games_played", 0)),
            "total_xp_earned": xp,
            "total_wins": wins_total,
            "total_completed": completed_total,
            "accuracy_pct": accuracy,
            "daily_streak": int(stats.get("daily_streak", 0)),
            "rank": rank,
            "ranks": list(RANKS),
            "best_scores": dict(stats.get("best_scores", {})),
        },
    })


@bp.post("/api/games/complete")
def api_games_complete():
    """Called after each finished round. Records a win + XP + (optionally) daily streak."""
    body = request.get_json(silent=True) or {}
    game_id = body.get("game_id") or ""
    won = bool(body.get("won", False))
    xp = int(body.get("xp") or 0)
    score = int(body.get("score") or 0)
    daily_date = body.get("daily_date")

    if not game_id:
        return jsonify({"success": False, "error": "game_id required"}), 400
    if xp < 0 or xp > 2000:
        xp = 0

    stats = _load_stats()
    stats = _broken_streak_check(stats)
    stats["total_games_played"] = int(stats.get("total_games_played", 0)) + 1
    stats["total_xp_earned"] = int(stats.get("total_xp_earned", 0)) + xp
    stats["games_finished"][game_id] = int(stats["games_finished"].get(game_id, 0)) + 1
    if won:
        stats["wins"][game_id] = int(stats["wins"].get(game_id, 0)) + 1
    prev_best = int(stats["best_scores"].get(game_id, 0))
    if score > prev_best:
        stats["best_scores"][game_id] = score

    # Daily streak handling (broken streak already enforced above via _broken_streak_check)
    if game_id == "daily_cipher" and daily_date and won:
        import datetime as _dt
        today = _dt.date.today().isoformat()
        if daily_date == today and stats.get("last_daily_complete_date") != today:
            stats["daily_streak"] = int(stats.get("daily_streak", 0)) + 1
            stats["last_daily_complete_date"] = today
        elif stats.get("last_daily_complete_date") != today:
            pass

    _save_stats(stats)

    if _USER_SERVICE_AVAILABLE and flask_session is not None:
        try:
            user = current_session_user(flask_session)
            if user and "username" in user:
                patch: Dict[str, Any] = {
                    "total_xp": int(stats.get("total_xp_earned", 0)),
                    "total_games_played": int(stats.get("total_games_played", 0)),
                    "total_wins": sum(int(v) for v in stats.get("wins", {}).values()),
                }
                prev_best = int(stats["best_scores"].get(game_id, 0))
                if prev_best:
                    patch.setdefault("best_scores", {})[game_id] = prev_best
                if game_id == "crazy_mode" and score:
                    patch.setdefault("best_scores", {})["crazy_mode_best"] = max(
                        int(patch.get("best_scores", {}).get("crazy_mode_best", 0)), score
                    )
                if game_id == "daily_cipher" and daily_date and won:
                    patch["daily_streak"] = int(stats.get("daily_streak", 0))
                    patch["last_daily_date"] = daily_date
                update_game_progress(user["username"], patch)
                try:
                    did = request.cookies.get("encryptsys_device_id") or ""
                    if did:
                        record_device_id(user["username"], did)
                except Exception:
                    pass
        except Exception as exc:  # pragma: no cover
            LOG.warning("Could not sync user game progress to Firestore: %s", exc)

    xp_total = int(stats.get("total_xp_earned", 0))
    rank = rank_for_xp(xp_total)
    wins_total = sum(int(v) for v in stats.get("wins", {}).values())
    completed_total = sum(int(v) for v in stats.get("games_finished", {}).values())
    return jsonify({
        "success": True,
        "statistics": {
            "total_games_played": int(stats["total_games_played"]),
            "total_xp_earned": xp_total,
            "total_wins": wins_total,
            "total_completed": completed_total,
            "accuracy_pct": round(100.0 * wins_total / completed_total, 1) if completed_total else 0,
            "daily_streak": int(stats.get("daily_streak", 0)),
            "rank": rank,
            "best_score_game": int(stats["best_scores"].get(game_id, 0)),
        },
    })


@bp.get("/api/games/leaderboard")
def api_games_leaderboard():
    """PUBLIC leaderboard — no authentication required.

    Returns up to N players sorted by XP desc. Includes this device if played.
    """
    try:
        limit = request.args.get("limit", default=20, type=int)
    except Exception:
        limit = 20
    safe_limit = max(3, min(100, int(limit or 20)))
    leaderboard = _build_leaderboard(limit=safe_limit)
    return jsonify({"success": True, "leaderboard": leaderboard})
