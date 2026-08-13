"""Quick diagnostic: import games module chain, start Flask test client, hit /games and /api/games/leaderboard."""
from __future__ import annotations

import sys
import traceback

print("=" * 70)
print("STEP 1: import crypto_games")
try:
    from utils.crypto_games import GAME_CATALOG, RANKS, rank_for_xp
    print(f"  OK: GAME_CATALOG has {len(GAME_CATALOG)} entries, RANKS = {[r['name'] for r in RANKS]}")
    for g in GAME_CATALOG:
        keys = sorted(g.keys())
        print(f"    id={g.get('id')!r}")
        print(f"      keys:          {keys}")
        print(f"      name:          {g.get('name')!r}")
        print(f"      has how_to_play = {'how_to_play' in g}  ({len(str(g.get('how_to_play','')))} chars)")
        print(f"      has example     = {'example' in g}  ({len(str(g.get('example','')))} chars)")
except Exception as e:
    print(f"  FAIL: {type(e).__name__}: {e}")
    traceback.print_exc()
    sys.exit(1)

print("=" * 70)
print("STEP 2: import games_routes")
try:
    from routes.games_routes import (
        bp as games_bp,
        _load_stats,
        _build_public_leaderboard,
        _broken_streak_check,
    )
    print("  OK: games_routes imported")
    stats = _load_stats()
    print(f"  stats keys = {sorted(stats.keys())}")
    print(f"  stats.total_xp_earned = {stats.get('total_xp_earned')}")
    print(f"  stats.daily_streak    = {stats.get('daily_streak')}")
    lb = _build_public_leaderboard(stats.get('total_xp_earned', 0))
    print(f"  leaderboard rows = {len(lb)}")
    for r in lb[:5]:
        print(f"    {r}")
except Exception as e:
    print(f"  FAIL: {type(e).__name__}: {e}")
    traceback.print_exc()
    sys.exit(2)

print("=" * 70)
print("STEP 3: import full Flask app, then hit /games via test client")
try:
    from app import app
    client = app.test_client()
    for path in ["/games", "/api/games/leaderboard", "/api/games/statistics", "/api/games/types"]:
        resp = client.get(path)
        ct = resp.content_type or ""
        print(f"  {path:<30s} -> status={resp.status_code}  bytes={len(resp.data)}  content-type={ct[:50]}")
        if resp.status_code != 200:
            print(f"    ---- 500 chars of body ----")
            try:
                print(resp.data.decode("utf-8", "replace")[:500])
            except Exception:
                print(resp.data[:500])
except Exception as e:
    print(f"  FAIL: {type(e).__name__}: {e}")
    traceback.print_exc()
    sys.exit(3)

print("=" * 70)
print("ALL DIAGNOSTIC STEPS PASSED")
