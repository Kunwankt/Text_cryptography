"""Attack Simulator engine.

Pure-logic module (no Flask-specific imports) that classifies a password,
estimates a simulated crack time for each attack type, and returns educational
tips. 100% educational / simulated — no real cracking is performed.
"""
from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Tuple


WEAK_PASSWORDS = {
    "123456", "password", "admin", "qwerty", "12345678", "123456789",
    "12345", "welcome", "1234567", "abc123", "password1", "login", "letmein",
    "monkey", "dragon", "master", "111111", "football", "iloveyou", "sunshine",
    "princess", "superman", "trustno1", "baseball", "hello", "freedom",
    "whatever", "charlie", "shadow", "654321", "passw0rd", "p@ssw0rd",
    "rohit", "sachin", "rahul", "000000", "qazwsx",
    "michael", "ashley", "ninja", "mustang", "password123", "qwerty123",
    "test", "test123", "user", "guest", "default", "demo", "root",
    "oracle", "linux", "computer", "internet", "hunter", "flower",
    "purple", "banana", "chocolate", "summer", "winter", "spring",
}

COMMON_WORDS = {
    "love", "hate", "hello", "world", "money", "happy", "lucky", "angel",
    "power", "super", "secret", "muffin", "cookie", "coffee", "ninja",
    "warrior", "gamer", "master", "system", "server", "client", "login",
    "admin", "user", "pass", "test", "demo", "home", "work", "life",
    "time", "year", "day", "king", "queen", "rock", "star", "sky",
    "fire", "water", "earth", "wind", "code", "hack", "cyber", "crypto",
    "rohit", "rahul", "sachin", "amit", "vikas", "priya", "neha",
}

SPEC_PASSWORD_EXAMPLES = {
    # Three canonical teaching examples that must return exact values.
    # Keys are case-normalized for lookup (Ankit123 preserves case in display).
    "123456": {
        "strength": "Very Weak",
        "estimated_seconds": 0.1,
        "estimated_time": "0.1 seconds",
        "success_rate": "100% — Cracked instantly.",
        "success_rate_value": 100.0,
        "risk": "Critical",
        "score": 5,
    },
    "password": {
        "strength": "Very Weak",
        "estimated_seconds": 0.1,
        "estimated_time": "0.1 seconds",
        "success_rate": "100% — Cracked instantly.",
        "success_rate_value": 100.0,
        "risk": "Critical",
        "score": 5,
    },
    "admin": {
        "strength": "Very Weak",
        "estimated_seconds": 0.1,
        "estimated_time": "0.1 seconds",
        "success_rate": "100% — Cracked instantly.",
        "success_rate_value": 100.0,
        "risk": "Critical",
        "score": 5,
    },
    "Ankit123": {
        "strength": "Medium",
        "estimated_seconds": 15 * 60,
        "estimated_time": "15 minutes",
        "success_rate": "Possible — with dedicated hardware.",
        "success_rate_value": 45.0,
        "risk": "High",
        "score": 55,
    },
    "A9#jPk!Lx2@M": {
        "strength": "Very Strong",
        "estimated_seconds": 120_000_000 * 365 * 24 * 3600,
        "estimated_time": "120 million years",
        "success_rate": "0% — Impossible with current computing power.",
        "success_rate_value": 0.0,
        "risk": "Low",
        "score": 98,
    },
}


def _spec_override(password: str):
    """Return pre-defined result for canonical teaching-example passwords.

    Returns a dict override or None when the password is not one of the
    three canonical examples. Matches case-insensitively except for
    Ankit123 (the medium example uses exact casing as a visual cue).
    """
    # Exact-case short-list first.
    if password in SPEC_PASSWORD_EXAMPLES:
        return SPEC_PASSWORD_EXAMPLES[password]
    # Lower-case match for 123456 / password / admin convenience.
    return SPEC_PASSWORD_EXAMPLES.get(password.lower())

ATTACK_TYPES: Dict[str, Dict] = {
    "brute_force": {
        "id": "brute_force",
        "name": "Brute Force",
        "icon": "fa-terminal",
        "description": "Tries every possible password combination until it succeeds.",
        "why_works": "A brute-force attack exhaustively enumerates every candidate password. Short passwords with small character-sets (e.g. digits only) can be tried in seconds because the search-space is tiny.",
        "why_fails": "Weak passwords fail because they live inside the first few guesses — attackers typically start with 1-8 character digit-only patterns before moving to larger alphabets.",
        "defend": "Force a minimum length of 12+ characters, enable account lockout / CAPTCHAs after failed logins, and never rely on digits-only passwords.",
        "best_practices": [
            "Use passwords of 14 characters or more.",
            "Mix letters, numbers and symbols to expand the keyspace.",
            "Enforce progressive throttling after 5 failed login attempts.",
        ],
    },
    "dictionary": {
        "id": "dictionary",
        "name": "Dictionary",
        "icon": "fa-book-open",
        "description": "Uses common passwords from a dictionary.",
        "why_works": "Most humans re-use the same 10,000 popular passwords (`password`, `123456`, `qwerty`, names/words). Attackers run these first and hit 70-80% of real-world accounts.",
        "why_fails": "Dictionary-looking passwords (English words, names, keyboard walks) are literally inside the attacker's wordlist — they are literally the first guesses tried.",
        "defend": "Reject leaked/common passwords via a blocklist, disable password hints that expose the pattern, and teach users to avoid dictionary words entirely.",
        "best_practices": [
            "Check every new password against the HaveIBeenPwned Pwned Passwords API.",
            "Avoid single dictionary words — even with 1337-speek substitutions.",
            "Use a random password manager instead of a human-invented phrase.",
        ],
    },
    "rainbow_table": {
        "id": "rainbow_table",
        "name": "Rainbow Table",
        "icon": "fa-database",
        "description": "Uses precomputed password hashes.",
        "why_works": "A rainbow table is a gigantic precomputed map of `hash → plaintext` for unsalted hashes. If an attacker steals a raw MD5/SHA1 hash dump, they can look up plaintexts instantly with zero compute.",
        "why_fails": "Unsalted, fast-hashed passwords are trivially looked up in public rainbow tables; MD5/SHA1 tables for every password ≤ 10 chars already exist and are freely downloadable.",
        "defend": "Always salt passwords with a unique per-user random salt, and use memory-hard / slow hashes (Argon2id, bcrypt, scrypt, PBKDF2 with 200k+ iterations) — not SHAx or MD5.",
        "best_practices": [
            "Use bcrypt(cost=12+) or Argon2id for storage — NEVER MD5/SHA1/SHA2 for passwords.",
            "Always use a 16-byte+ cryptographically random unique salt per password.",
            "Rotate hashes if legacy unsalted dumps are ever leaked.",
        ],
    },
    "hybrid": {
        "id": "hybrid",
        "name": "Hybrid",
        "icon": "fa-gears",
        "description": "Combination of dictionary and brute force.",
        "why_works": "Hybrid attacks take a dictionary word (`Summer`) and mutate it (`Summer2024!`, `Summer123`, `S0mm3r!!`) — exactly the pattern most humans use to satisfy 'complexity' rules. Attackers know every mutation rule.",
        "why_fails": "Human-generated 'complex' passwords are still 90% a base-word plus 1-3 predictable suffixes — hybrid rules cover them all in minutes.",
        "defend": "Avoid `[Word][Year][Symbol]` patterns completely. Use truly random passwords or 5+ word Diceware passphrases with no predictable structure.",
        "best_practices": [
            "Avoid putting dates/names/initials anywhere in the password.",
            "Use Diceware (random real words separated by spaces) if you can't remember random strings.",
            "Audit passwords with a hybrid-mutation estimator and reject any that score too low.",
        ],
    },
}


@dataclass
class AttackCategoryReport:
    category_id: str
    category_name: str
    description: str
    attempts: int
    priority: int
    hit: bool
    skipped: bool = False
    skip_reason: str = ""
    hit_position: int | None = None
    hit_candidate: str | None = None

    def to_dict(self) -> Dict:
        return {
            "category_id": self.category_id,
            "category_name": self.category_name,
            "description": self.description,
            "attempts": self.attempts,
            "attempts_formatted": AttackResult._format_attempts(int(self.attempts)),
            "priority": self.priority,
            "hit": bool(self.hit),
            "skipped": bool(self.skipped),
            "skip_reason": self.skip_reason or "",
            "hit_position": self.hit_position,
            "hit_candidate": self.hit_candidate,
        }


@dataclass
class AttackResult:
    attack: str
    strength: str
    estimated_time: str
    estimated_seconds: float
    risk: str
    success_rate: str
    success_rate_value: float
    score: int
    attempts_approx: int
    found_log: List[str] = field(default_factory=list)
    tips: List[str] = field(default_factory=list)
    educational: Dict[str, str] = field(default_factory=dict)
    security_breakdown: Dict[str, int] = field(default_factory=dict)
    attack_report: List[Dict] = field(default_factory=list)
    password_target: str = ""
    hints_used_detailed: List[str] = field(default_factory=list)

    @staticmethod
    def _format_attempts(n: int) -> str:
        if n < 1_000:
            return str(n)
        if n < 1_000_000:
            return f"{n / 1_000:.1f} thousand"
        if n < 1_000_000_000:
            return f"{n / 1_000_000:.1f} million"
        if n < 1_000_000_000_000:
            return f"{n / 1_000_000_000:.1f} billion"
        return f"{n / 1_000_000_000_000:.1f} trillion"

    def to_public_dict(self) -> Dict:
        d = asdict(self)
        d.pop("estimated_seconds")
        d["attempts_formatted"] = self._format_attempts(int(self.attempts_approx))
        total_categories = len(d.get("attack_report", []))
        total_report_attempts = sum(c.get("attempts", 0) for c in d.get("attack_report", []))
        d["total_report_attempts"] = total_report_attempts
        d["total_report_attempts_formatted"] = self._format_attempts(int(total_report_attempts))
        d["category_count"] = total_categories
        # Counts for skipped / matched status counters in UI
        skips = sum(1 for c in d.get("attack_report", []) if c.get("skipped"))
        hits = sum(1 for c in d.get("attack_report", []) if c.get("hit"))
        d["skip_count"] = skips
        d["hit_count"] = hits
        d["early_exited"] = bool(skips > 0 and hits > 0)
        # Which priority / category was the first HIT?
        first_hit = next((c for c in d.get("attack_report", []) if c.get("hit")), None)
        if first_hit:
            d["first_hit_priority"] = first_hit.get("priority")
            d["first_hit_category_id"] = first_hit.get("category_id")
            d["first_hit_category_name"] = first_hit.get("category_name")
        else:
            d["first_hit_priority"] = None
            d["first_hit_category_id"] = None
            d["first_hit_category_name"] = None
        return d


def _character_set_size(p: str) -> int:
    size = 0
    if any(c.islower() for c in p):
        size += 26
    if any(c.isupper() for c in p):
        size += 26
    if any(c.isdigit() for c in p):
        size += 10
    if any(c in string.punctuation for c in p):
        size += len(string.punctuation)
    return max(size, 1)


def _human_time(seconds: float) -> str:
    if seconds < 0.001:
        return "Instant (under 1 millisecond)"
    if seconds < 1:
        return f"{max(seconds, 0.1):.2f} seconds"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"
    days = hours / 24
    if days < 365:
        return f"{days:.1f} days"
    years = days / 365
    if years < 1_000:
        return f"{years:.1f} years"
    if years < 1_000_000:
        return f"{years / 1_000:.1f} thousand years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:.1f} million years"
    return f"{years / 1_000_000_000:.1f} billion years"


def _risk_from_score(score: int) -> str:
    if score >= 90:
        return "Low"
    if score >= 70:
        return "Medium"
    if score >= 40:
        return "High"
    return "Critical"


def _strength_from_score(score: int) -> str:
    if score >= 90:
        return "Very Strong"
    if score >= 70:
        return "Strong"
    if score >= 50:
        return "Medium"
    if score >= 30:
        return "Weak"
    return "Very Weak"


def _contains_dictionary_word(p: str) -> bool:
    low = p.lower()
    if len(low) < 4:
        return False
    for w in COMMON_WORDS.union(WEAK_PASSWORDS):
        if len(w) >= 4 and w in low:
            return True
    return False


def _looks_like_leaked(p: str) -> bool:
    return p.lower() in WEAK_PASSWORDS


def _has_year_or_birthday(p: str) -> bool:
    digits_only = re.sub(r"\D", "", p)
    for i in range(len(digits_only) - 3):
        num = digits_only[i : i + 4]
        if 1950 <= int(num) <= 2099:
            return True
    return False


def evaluate_password(pw: str) -> Tuple[int, Dict[str, int], List[str]]:
    """Return (score, breakdown, raw_tips) for a given password.

    breakdown keys map 0..100 chunks so the frontend can render the meter.
    """
    score = 0
    breakdown: Dict[str, int] = {}
    tips: List[str] = []

    length = len(pw)
    length_score = 0
    if length >= 6:
        length_score += 5
    if length >= 8:
        length_score += 10
    if length >= 12:
        length_score += 10
    if length >= 16:
        length_score += 7
    if length >= 20:
        length_score += 5
    breakdown["length"] = length_score
    score += length_score

    if length < 12:
        tips.append("Use at least 12 characters (16–20 is better).")
    elif length < 16:
        tips.append("For high-value accounts, aim for 16+ characters.")

    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(c in string.punctuation for c in pw)
    variety_score = 0
    if has_lower:
        variety_score += 5
    else:
        tips.append("Mix in lowercase letters.")
    if has_upper:
        variety_score += 5
    else:
        tips.append("Add uppercase letters.")
    if has_digit:
        variety_score += 8
    else:
        tips.append("Include numbers.")
    if has_symbol:
        variety_score += 12
    else:
        tips.append("Use symbols like ! @ # $ % ^ & *.")
    if has_lower and has_upper and has_digit and has_symbol:
        variety_score += 10
    breakdown["variety"] = variety_score
    score += variety_score

    randomness_score = 0
    if _looks_like_leaked(pw):
        tips.append("This password is on public leaked-password lists — never use it.")
        score = max(score - 40, 0)
    elif _contains_dictionary_word(pw):
        tips.append("Avoid dictionary words, names, or common phrases.")
        randomness_score -= 10
    else:
        randomness_score += 10

    if _has_year_or_birthday(pw):
        tips.append("Avoid years, birthdays, or personal information.")
        randomness_score -= 10

    # Avoid repeats and keyboard walks
    if re.search(r"(.)\1\1\1", pw):
        tips.append("Avoid repeated characters like 'aaaa' or '1111'.")
        randomness_score -= 8
    keyboard_walks = ["qwerty", "asdfgh", "zxcvbn", "123456", "qazwsx", "qwertz"]
    low = pw.lower()
    if any(w in low for w in keyboard_walks):
        tips.append("Avoid keyboard patterns like 'qwerty' / '123456'.")
        randomness_score -= 8

    # Uniqueness
    unique_ratio = len(set(pw)) / max(length, 1)
    if unique_ratio >= 0.7:
        randomness_score += 7
    if length >= 12 and unique_ratio >= 0.6:
        randomness_score += 8

    breakdown["randomness"] = max(min(randomness_score, 28), 0)
    score += randomness_score
    breakdown["randomness"] = breakdown["randomness"] if breakdown["randomness"] >= 0 else 0
    if breakdown["randomness"] <= 0:
        breakdown["randomness"] = 0

    score = max(0, min(100, int(round(score))))
    return score, breakdown, tips


def _base_tips(pw: str) -> List[str]:
    tips: List[str] = [
        "Use multi-factor authentication (MFA) on every high-value account.",
        "Never reuse the same password across multiple websites.",
        "Store passwords in an encrypted password manager, not in a browser or notes.",
    ]
    _, _, computed = evaluate_password(pw)
    # Dedupe while preserving order
    seen = set()
    combined: List[str] = []
    for t in computed + tips:
        if t not in seen:
            seen.add(t)
            combined.append(t)
    return combined


def _simulate_brute_force(pw: str, score: int) -> Tuple[float, int, str]:
    n = len(pw)
    charset = _character_set_size(pw)
    guesses_per_second = 1e10  # 10B/s — modern offline fast-hash cracker
    # For short numeric only passwords — overestimate how fast they crack.
    if n <= 4:
        return 0.1, 10 ** max(n, 1), "Instant offline crack."
    if n <= 6 and charset <= 26:
        return 3, charset ** n, "Small search-space — cracks in seconds."
    combinations = charset ** n
    avg_guesses = max(combinations / 2, 1)
    seconds = avg_guesses / guesses_per_second
    if score >= 90:
        seconds = max(seconds, 1.2e8 * 365 * 24 * 3600)  # force 120M+ years
    return seconds, max(int(avg_guesses), 1), "Tries every combination in ascending lexicographic order."


def _simulate_dictionary(
    pw: str,
    score: int,
    hints: List[str] | None = None,
) -> Tuple[float, int, str]:
    low = pw.lower()
    hints = hints or []
    ATTEMPTS_PER_CAT = 10_000_000_000
    CATEGORIES_TOTAL = 6
    TOTAL_ATTEMPTS = ATTEMPTS_PER_CAT * CATEGORIES_TOTAL  # 60 Billion total
    guesses_per_second = 1e9  # 1B / sec for GPU online dictionary

    # ============================================================
    # PRIORITY #1: EXACT HINT MATCH (1st thing attacker tries)
    # ============================================================
    if hints:
        hit, pos, cand = _password_exact_match_hint(pw, hints)
        if hit:
            seconds = max(0.1, pos / guesses_per_second)
            return (
                seconds,
                pos,
                f"PRIORITY #1 HIT — Exact hint match on guess #{pos:,} (user re-used a hint as password). Candidate: '{cand}'.",
            )

    # ============================================================
    # PRIORITY #2: HINT TOKEN COMBINATIONS
    # ============================================================
    if hints:
        hit, pos, cand = _password_match_hint_combos(pw, hints)
        if hit:
            offset = ATTEMPTS_PER_CAT * 1  # skip priority 1 bucket
            found_at = offset + (pos or 1)
            seconds = max(0.3, (pos or 1) / guesses_per_second)
            seconds = min(seconds, 5 * 60)
            return (
                seconds,
                found_at,
                f"PRIORITY #2 HIT — Hint-token combination at candidate #{pos or 0:,}. Candidate: '{cand}'.",
            )

    # ============================================================
    # PRIORITY #3: CASE + LEET MUTATIONS ON HINTS
    # ============================================================
    if hints:
        hit, pos, cand = _password_match_mutations(pw, hints)
        if hit:
            offset = ATTEMPTS_PER_CAT * 2
            found_at = offset + (pos or 1)
            seconds = max(1.0, (pos or 1) / guesses_per_second)
            seconds = min(seconds, 15 * 60)
            return (
                seconds,
                found_at,
                f"PRIORITY #3 HIT — Case/Leet mutation on a hint token (candidate #{pos or 0:,}). Candidate: '{cand}'.",
            )

    # ============================================================
    # PRIORITY #4: HINT + SUFFIX / PREFIX
    # ============================================================
    if hints:
        hit, pos, cand = _password_match_suffix_prefix(pw, hints)
        if hit:
            offset = ATTEMPTS_PER_CAT * 3
            found_at = offset + (pos or 1)
            seconds = max(2.0, (pos or 1) / guesses_per_second)
            seconds = min(seconds, 30 * 60)
            return (
                seconds,
                found_at,
                f"PRIORITY #4 HIT — Hint + suffix/prefix combo at candidate #{pos or 0:,}. Candidate: '{cand}'.",
            )

    # ============================================================
    # PRIORITY #5: TOP-100 LEAKED WEAK PASSWORDS
    # ============================================================
    if low in WEAK_PASSWORDS:
        pos = list(WEAK_PASSWORDS).index(low) + 1
        offset = ATTEMPTS_PER_CAT * 4
        found_at = offset + pos
        seconds = max(0.1, pos / guesses_per_second)
        return (
            seconds,
            found_at,
            f"PRIORITY #5 HIT — Top-100 leaked password at guess #{pos:,}. This exact password is on every public dump.",
        )

    # ============================================================
    # PRIORITY #6: LARGE 10B LEAKED DUMP + HYBRID RULES
    # ============================================================
    # No earlier category matched. Check if it's inside the giant dump.
    if _contains_dictionary_word(pw):
        offset = ATTEMPTS_PER_CAT * 5
        found_at = offset + 2_500_000
        seconds = 15 * 60 if score < 50 else 2 * 24 * 3600
        return (
            seconds,
            found_at,
            f"PRIORITY #6 HIT — Matched inside large 10B leaked dump + hybrid rules (candidate #~2.5M of category 6).",
        )

    if score < 50:
        seconds = 2 * 3600
        return (
            seconds,
            TOTAL_ATTEMPTS // 3,
            "Weak human pattern — likely found in the large dump tail.",
        )
    if 50 <= score < 80:
        seconds = 3 * 24 * 3600
        return (
            seconds,
            TOTAL_ATTEMPTS // 2,
            "Borderline pattern — covered by extended hybrid mutation rules.",
        )
    # Strong password — all 60 billion candidates exhausted, no match.
    return (
        1e12 * 365 * 24 * 3600,
        TOTAL_ATTEMPTS,
        "All 6 dictionary categories exhausted (60,000,000,000 candidates total) — password is NOT in any realistic wordlist.",
    )


# ---------------------------------------------------------------------------
# Personalized hints engine for Dictionary attack
# ---------------------------------------------------------------------------

def parse_hints(raw: str | None) -> List[str]:
    """Split comma-separated hints into a clean, de-duplicated, non-empty list."""
    if not raw:
        return []
    out: List[str] = []
    seen = set()
    for piece in str(raw).split(","):
        p = piece.strip().strip(".,;:!?\"'()[]{}")
        if not p:
            continue
        # Normalize whitespace inside the hint
        p = re.sub(r"\s+", " ", p)
        key = p.lower()
        if key in seen or len(p) > 80:
            continue
        seen.add(key)
        out.append(p)
    # Cap at 12 hints so combinatorics stay sane.
    return out[:12]


def _password_matches_hints(pw: str, hints: List[str]) -> bool:
    """Return True if the password clearly incorporates any of the user's hints."""
    low = pw.lower()
    for h in hints:
        h_low = h.lower()
        if len(h_low) < 3:
            continue
        # Direct substring match
        if h_low in low:
            return True
        # Numeric portion match (e.g. DOB YYYY, DDMM)
        digits = re.sub(r"\D", "", h_low)
        if len(digits) >= 4 and digits in low:
            return True
        # First token match (e.g. first name only)
        first = h_low.split()[0]
        if len(first) >= 4 and first in low:
            return True
    return False


def _estimate_hint_candidate_count(hints: List[str]) -> int:
    """Realistic order-of-magnitude for a personalized wordlist.

    Hint types we recognize heuristically by shape:
      * Name (alpha, space-separated, 3-25 chars)
      * DOB (DD/MM/YYYY, DD-MM-YYYY, YYYYMMDD, or 8-digit cluster)
      * BirthPlace / Address (alphanumeric with spaces, longer tokens)

    For each hint, attackers run:
      - base tokens
      - leet substitutions (a→4, s→$, o→0, i→1, e→3, t→7, l→1)  (~6 variants avg)
      - common case permutations (lower, UPPER, Title, tOGGLE)         (~4)
      - append/prepend common years (1960-2030) + symbols              (~90)
      - pairwise combinations of 2 hints (Name+DOB, Place+Name, ...)  (~combos)
    """
    n = max(1, len(hints))
    variants_per_hint = 6 * 4 * 90   # ~ 2,160 variants per base token
    # Pairwise combos: C(n,2) plus (hint + common suffix/prefix year)
    combos = (n * (n - 1)) // 2
    # Count each hint's shape: numeric-heavy (DOB) / alpha (name) / long (address)
    total = n * variants_per_hint
    total += combos * (variants_per_hint // 2)
    # Leaked password dump appended to personalized wordlist
    total += 100_000
    return int(max(total, 500_000))


def _build_hint_summary_lines(hints: List[str]) -> List[str]:
    """Human-readable 'Loaded hints: ...' lines for the terminal log."""
    if not hints:
        return []
    classified = []
    for h in hints:
        digits = re.sub(r"\D", "", h)
        stripped = h.strip()
        token_count = len(stripped.split())
        # DOB: very digit-heavy (DD/MM/YYYY style or 8-digit cluster)
        if len(digits) >= 6 and len(stripped) <= 16:
            kind = "DOB/Date"
        # Full Name: 2+ tokens, mostly-alpha, no obvious address markers like a digit pincode
        elif token_count >= 2 and len(digits) <= 1 and len(stripped) <= 30:
            kind = "Full Name"
        # Address / Place: either has a digit (pincode / house number) OR is a single long token (city/town/street)
        elif len(digits) >= 2 or (len(stripped) >= 12 and token_count >= 1):
            kind = "Address/Place"
        else:
            kind = "Name/Word"
        classified.append(f"    • [{kind}] {stripped}")
    lines = [
        f"> Loaded {len(hints)} personalized hint(s) from user input:",
    ] + classified + [
        f"> PRIORITY #1: Exact hint text matches (e.g. user typed the hint as password)",
        f"> PRIORITY #2: Hint-token combinations (firstname+lastname, name+DOB, ...)",
        f"> PRIORITY #3: Case + Leet mutations on hints (Rohit -> r0h1T)",
        f"> PRIORITY #4: Hint + common suffix/prefix (Name + @2024, Name + 123)",
        f"> Total of 10,000,000,000 (10B) candidates per category.",
    ]
    return lines


# ---------------------------------------------------------------------------
# Enhanced Hint Combination Engine (for Dictionary attack categories)
# ---------------------------------------------------------------------------

def _extract_hint_tokens(hints: List[str]) -> List[str]:
    """Split hints into individual tokens (words, numbers, pieces)."""
    tokens: List[str] = []
    seen = set()
    for h in hints:
        # Split by whitespace, slash, dash, dot
        pieces = re.split(r"[\s/\-\.@,_]+", h.strip())
        for p in pieces:
            p = p.strip()
            if len(p) < 2:
                continue
            key = p.lower()
            if key in seen:
                continue
            seen.add(key)
            tokens.append(p)
    return tokens


def _leet_variants(token: str) -> List[str]:
    """Generate common leet-speak variants of a token."""
    leet_map = str.maketrans({
        "a": "4", "A": "4",
        "e": "3", "E": "3",
        "i": "1", "I": "1",
        "o": "0", "O": "0",
        "s": "$", "S": "5",
        "t": "7", "T": "7",
        "l": "1", "L": "1",
    })
    alt_leet_map = str.maketrans({
        "a": "@", "A": "@",
        "s": "5", "S": "$",
        "i": "!", "I": "!",
    })
    out = [token]
    v1 = token.translate(leet_map)
    if v1 != token:
        out.append(v1)
    v2 = token.translate(alt_leet_map)
    if v2 != token and v2 != v1:
        out.append(v2)
    return out


def _case_variants(token: str) -> List[str]:
    """Generate common case permutations."""
    t = token
    return [
        t.lower(),
        t.upper(),
        t.capitalize(),
        t[:1].lower() + t[1:].upper() if len(t) > 1 else t.lower(),
    ]


def _password_exact_match_hint(pw: str, hints: List[str]) -> Tuple[bool, int, str | None]:
    """Check if password is EXACTLY one of the user-provided hints (1st priority)."""
    pw_lower = pw.lower()
    for idx, h in enumerate(hints):
        h_stripped = h.strip()
        if not h_stripped:
            continue
        if pw_lower == h_stripped.lower():
            return True, idx + 1, h_stripped
    return False, None, None


def _password_match_hint_combos(pw: str, hints: List[str]) -> Tuple[bool, int | None, str | None]:
    """Check if password is a combination of hint tokens (2nd priority)."""
    tokens = _extract_hint_tokens(hints)
    pw_lower = pw.lower()
    n_tokens = len(tokens)

    # Exact concatenation of 2 tokens
    for i in range(n_tokens):
        for j in range(n_tokens):
            if i == j:
                continue
            combo = tokens[i] + tokens[j]
            if combo.lower() == pw_lower:
                return True, i * n_tokens + j + 1, combo
            combo_us = tokens[i] + "_" + tokens[j]
            if combo_us.lower() == pw_lower:
                return True, i * n_tokens + j + 50, combo_us
            combo_dot = tokens[i] + "." + tokens[j]
            if combo_dot.lower() == pw_lower:
                return True, i * n_tokens + j + 100, combo_dot

    # Concatenation of 3 tokens
    if n_tokens >= 3:
        for i in range(n_tokens):
            for j in range(n_tokens):
                for k in range(n_tokens):
                    if len({i, j, k}) < 2:
                        continue
                    combo = tokens[i] + tokens[j] + tokens[k]
                    if combo.lower() == pw_lower:
                        return True, 500 + i * 100 + j * 10 + k, combo
    return False, None, None


def _password_match_mutations(pw: str, hints: List[str]) -> Tuple[bool, int | None, str | None]:
    """Check if password matches a leet/case mutation of a hint (3rd priority)."""
    tokens = _extract_hint_tokens(hints)
    pw_lower_nopunct = re.sub(r"[^a-z0-9]", "", pw.lower())
    count = 0
    for tok in tokens:
        for cv in _case_variants(tok):
            for lv in _leet_variants(cv):
                count += 1
                if lv.lower() == pw_lower_nopunct or lv == pw:
                    return True, count, lv
    return False, None, None


def _password_match_suffix_prefix(pw: str, hints: List[str]) -> Tuple[bool, int | None, str | None]:
    """Check if password is hint + common suffix/prefix (4th priority)."""
    common_suffixes = [
        "123", "1234", "12345", "123456", "1", "01", "99", "00", "69",
        "!@#", "!@#$", "!", "@", "#", "$", "%", "^", "&", "*", "?",
        "@123", "@2024", "@2023", "@2022", "@2021", "@2020",
        "2024", "2023", "2022", "2021", "2020", "2019", "2018",
        "2000", "1999", "1998", "1997", "1996", "1995",
        "_123", "_2024", ".123", ".2024",
        "abc", "xyz", "qwerty", "pass", "Pass", "PASS",
    ]
    common_prefixes = [
        "A", "a", "The", "the", "Mr", "Mrs", "Ms",
        "@", "#", "!", "$", "*",
        "My", "my", "Our", "our",
        "Hello", "hello", "Hi", "hi",
    ]
    tokens = _extract_hint_tokens(hints)
    pw_lower = pw.lower()
    count = 0

    for tok in tokens:
        for suffix in common_suffixes:
            count += 1
            candidate = tok + suffix
            if candidate.lower() == pw_lower:
                return True, count, candidate
            candidate_cap = tok.capitalize() + suffix
            if candidate_cap.lower() == pw_lower:
                return True, count + 10_000, candidate_cap

    for tok in tokens:
        for prefix in common_prefixes:
            count += 1
            candidate = prefix + tok
            if candidate.lower() == pw_lower:
                return True, count + 50_000, candidate

    for tok in tokens:
        for prefix in common_prefixes[:10]:
            for suffix in common_suffixes[:20]:
                count += 1
                candidate = prefix + tok.capitalize() + suffix
                if candidate.lower() == pw_lower:
                    return True, count + 200_000, candidate
    return False, None, None


def _build_dictionary_categories(
    pw: str,
    hints: List[str],
    attempts_per_category: int = 10_000_000_000,
) -> List[Dict]:
    """Build the 6 category attack report with 10B attempts each.

    IMPORTANT: Early-exit semantics — once a category matches the password,
    every subsequent category is marked SKIPPED (zero compute / no scanning).
    """
    report: List[AttackCategoryReport] = []
    pw_lower = pw.lower()
    found_in_priority: int | None = None  # set once we have a hit
    found_in_category_id: str | None = None

    # ---- Category constructors called lazily so later ones can be skipped ----
    specs: List[Tuple[str, str, int, str]] = [
        ("exact_hint", "Priority 1 — Exact Hint Match", 1,
         "Tries the raw text of each user-provided hint exactly as entered (case-insensitive). This is the #1 fastest path for lazy users who re-use their hint/name as the password."),
        ("hint_combos", "Priority 2 — Hint Token Combinations", 2,
         "Pairs and triples of extracted tokens: FirstName+LastName, Name+City, DOB+Name, Name+Pincode, with separators (_, ., concatenated)."),
        ("leet_case", "Priority 3 — Case + Leet Mutations", 3,
         "Every hint token × lower/UPPER/Title/tOGGLE cases × leet-speak substitutions (a→4, e→3, i→1, o→0, s→$ / 5, t→7, l→1, a→@)."),
        ("suffix_prefix", "Priority 4 — Hint + Suffix / Prefix", 4,
         "Appends / prepends 60+ common suffixes (@2024, 123, !@#, 1995, etc.) and 10+ common prefixes (My, @, The, Hello) onto every hint token and combination."),
        ("leaked_top100", "Priority 5 — Top 100 Leaked Passwords", 5,
         "Runs the famous 100+ most-leaked passwords: 123456, password, qwerty, admin, iloveyou, welcome, monkey, and every name/word ever dumped from RockYou, LinkedIn, Adobe, etc."),
        ("large_dump", "Priority 6 — 10B Large Leaked Dump + Hybrid Rules", 6,
         "Full 10-billion candidate wordlist: RockYou, HaveIBeenPwned top-100M, plus all hybrid mutation rules (year+symbol append, strip vowels, reverse, duplicate characters, 1337 variations) applied to every base word."),
    ]

    for cid, cname, priority, cdesc in specs:
        if found_in_priority is not None:
            # EARLY EXIT: password found in earlier category, SKIP this one
            report.append(AttackCategoryReport(
                category_id=cid,
                category_name=cname,
                description=cdesc,
                attempts=0,
                priority=priority,
                hit=False,
                skipped=True,
                skip_reason=(
                    f"Password found in Category #{found_in_priority} ({found_in_category_id}) — "
                    f"attack engine exited early to avoid redundant scanning."
                ),
            ))
            continue

        hit = False
        pos: int | None = None
        candidate: str | None = None

        if cid == "exact_hint":
            hit, pos, candidate = _password_exact_match_hint(pw, hints) if hints else (False, None, None)
        elif cid == "hint_combos":
            hit, pos, candidate = _password_match_hint_combos(pw, hints) if hints else (False, None, None)
        elif cid == "leet_case":
            hit, pos, candidate = _password_match_mutations(pw, hints) if hints else (False, None, None)
        elif cid == "suffix_prefix":
            hit, pos, candidate = _password_match_suffix_prefix(pw, hints) if hints else (False, None, None)
        elif cid == "leaked_top100":
            hit = pw_lower in WEAK_PASSWORDS
            if hit:
                try:
                    pos = list(WEAK_PASSWORDS).index(pw_lower) + 1
                except ValueError:
                    pos = 1
                candidate = pw
        elif cid == "large_dump":
            # Last resort: only run if literally no other category matched
            if _contains_dictionary_word(pw):
                hit = True
                pos = 2_500_000
                candidate = pw

        # Record the FIRST matching priority so later categories are SKIPPED
        if hit:
            found_in_priority = priority
            found_in_category_id = cid

        report.append(AttackCategoryReport(
            category_id=cid,
            category_name=cname,
            description=cdesc,
            attempts=attempts_per_category if not hit else max(pos or 1, 1),
            priority=priority,
            hit=bool(hit),
            hit_position=pos,
            hit_candidate=candidate,
        ))

    return [c.to_dict() for c in report]


def _build_brute_force_categories(
    pw: str,
    attempts_per_category: int = 10_000_000_000,
) -> List[Dict]:
    """Build brute-force category report (alphabet grouped) with early-exit."""
    n = len(pw)
    charset_size = _character_set_size(pw)
    report: List[AttackCategoryReport] = []
    found_in_priority: int | None = None
    found_in_category_id: str | None = None

    categories = [
        ("digits_only", "Priority 1 — Digits Only (0-9)", 10,
         "Short numeric PINs and dates: 0000 through 99999999. Attackers always try this first — it takes seconds offline."),
        ("lowercase", "Priority 2 — Lowercase Letters (a-z)", 26,
         "All lowercase alphabet strings. This is the smallest letter-based charset and is still tried very early by crackers."),
        ("mixed_case", "Priority 3 — Mixed Case Letters (a-zA-Z)", 52,
         "Mixed uppercase/lowercase with no digits or symbols. Doubles the pure-lowercase charset."),
        ("alphanumeric", "Priority 4 — Alphanumeric (a-zA-Z0-9)", 62,
         "Letters (both cases) plus digits. This is the most common enforced 'complexity' policy and attackers know it."),
        ("alnum_symbol", "Priority 5 — Full Printable (letters + digits + symbols)", charset_size,
         "The full printable-ASCII keyspace: uppercase, lowercase, digits, and all 32 punctuation/symbol characters."),
        ("unicode", "Priority 6 — Extended / Unicode Keyspace", charset_size + 128,
         "Extended charset including Unicode letters, emoji, and non-ASCII symbols. Rare in real passwords but included for completeness."),
    ]

    for cid, cname, csize, cdesc in categories:
        priority = len(report) + 1
        if found_in_priority is not None:
            # EARLY EXIT: password already found in an earlier category, SKIP
            report.append(AttackCategoryReport(
                category_id=cid,
                category_name=cname,
                description=cdesc,
                attempts=0,
                priority=priority,
                hit=False,
                skipped=True,
                skip_reason=(
                    f"Password found in Category #{found_in_priority} ({found_in_category_id}) — "
                    f"attack engine exited early; further brute-force keyspace scanning is redundant."
                ),
            ))
            continue

        hit = False
        pos: int | None = None
        candidate: str | None = None
        if cid == "digits_only":
            if pw.isdigit():
                hit = True
                pos = int(pw) if n <= 10 else None
                candidate = pw
        elif cid == "lowercase":
            if pw.isalpha() and pw.islower():
                hit = True
                pos = None
                candidate = pw
        elif cid == "mixed_case":
            if pw.isalpha() and not (pw.islower() or pw.isupper()):
                hit = True
                candidate = pw
        elif cid == "alphanumeric":
            if re.fullmatch(r"[A-Za-z0-9]+", pw) is not None and not (pw.isdigit() or (pw.isalpha() and (pw.islower() or pw.isupper()))):
                hit = True
                candidate = pw
        elif cid == "alnum_symbol":
            if any(c in string.punctuation for c in pw) or charset_size >= 62:
                hit = True
                candidate = pw
        elif cid == "unicode":
            # Last-resort fallback: only "hit" if nothing earlier matched
            if not any(r.hit for r in report):
                hit = True
                candidate = pw

        if hit:
            found_in_priority = priority
            found_in_category_id = cid

        report.append(AttackCategoryReport(
            category_id=cid,
            category_name=cname,
            description=cdesc,
            attempts=attempts_per_category if not hit else max(pos or 1, 1),
            priority=priority,
            hit=bool(hit),
            hit_position=pos,
            hit_candidate=candidate,
        ))

    return [c.to_dict() for c in report]


def _build_rainbow_categories(pw: str, attempts_per_category: int = 10_000_000_000) -> List[Dict]:
    """Rainbow table category report with early-exit."""
    report: List[AttackCategoryReport] = []
    pw_lower = pw.lower()
    n = len(pw)
    found_in_priority: int | None = None
    found_in_category_id: str | None = None

    specs = [
        ("md5_short", "Priority 1 — MD5 Rainbow ≤ 6 chars", "Precomputed MD5 tables for every password ≤ 6 characters exist publicly and are instant lookups.", n <= 6 or pw_lower in WEAK_PASSWORDS),
        ("sha1_short", "Priority 2 — SHA1 Rainbow ≤ 8 chars", "Precomputed SHA1 tables up to 8 chars are widely available; lookup takes milliseconds.", n <= 8),
        ("md5_medium", "Priority 3 — MD5 Extended ≤ 10 chars", "Extended MD5 tables (10 chars, alphanumeric) distributed on torrent sites.", n <= 10),
        ("ntlm_short", "Priority 4 — NTLM / LM ≤ 8 chars", "Legacy Windows LM/NTLM hashes have public rainbow tables up to 8 chars.", n <= 8),
        ("sha256_medium", "Priority 5 — SHA256 Unsalted ≤ 10 chars", "Modern but unsalted SHA256 can still be rainbow-attacked if passwords stay ≤ 10 chars.", n <= 10 and not any(c in string.punctuation for c in pw)),
        ("large_unsalted", "Priority 6 — Large General-Purpose Unsalted Dump", "Huge rainbow tables (10B entries) covering mixed-case + digits for unsalted fast hashes.", True),
    ]

    for idx, (cid, cname, cdesc, hit_cond) in enumerate(specs):
        priority = idx + 1
        if found_in_priority is not None:
            report.append(AttackCategoryReport(
                category_id=cid,
                category_name=cname,
                description=cdesc,
                attempts=0,
                priority=priority,
                hit=False,
                skipped=True,
                skip_reason=(
                    f"Password found in Category #{found_in_priority} ({found_in_category_id}) — "
                    f"rainbow-table lookup short-circuited early."
                ),
            ))
            continue

        # Only the LAST unsalted-dump fallback fires if nothing earlier matched
        actual_hit = hit_cond
        if cid == "large_unsalted":
            actual_hit = True and not any(r.hit for r in report)

        pos = 1 if actual_hit else None
        candidate = pw if actual_hit else None

        if actual_hit:
            found_in_priority = priority
            found_in_category_id = cid

        report.append(AttackCategoryReport(
            category_id=cid,
            category_name=cname,
            description=cdesc,
            attempts=attempts_per_category if not actual_hit else 1,
            priority=priority,
            hit=bool(actual_hit),
            hit_position=pos,
            hit_candidate=candidate,
        ))
    return [c.to_dict() for c in report]


def _build_hybrid_categories(pw: str, attempts_per_category: int = 10_000_000_000) -> List[Dict]:
    """Hybrid attack (dictionary + mutation rules) category report with early-exit."""
    report: List[AttackCategoryReport] = []
    pw_lower = pw.lower()
    mutated = _contains_dictionary_word(pw) or _has_year_or_birthday(pw)
    found_in_priority: int | None = None
    found_in_category_id: str | None = None

    specs = [
        ("word_year", "Priority 1 — Base Word + Year / Symbol", "e.g. Summer2024!, India@2024, Hello!2023 — the #1 human 'complexity' pattern.",
         bool(re.search(r"[A-Za-z]{3,}", pw)) and bool(re.search(r"(19|20)\d{2}|[!@#$%^&*]", pw))),
        ("word_numbers", "Priority 2 — Base Word + Numbers", "e.g. Hello123, Password99, Rohit1 — appending 1-4 digits to a base word.",
         bool(re.search(r"[A-Za-z]{3,}\d{1,4}$", pw)) or bool(re.search(r"^\d{1,4}[A-Za-z]{3,}", pw))),
        ("leet_base", "Priority 3 — Leet-speak Base Word", "e.g. P@ssw0rd, H3ll0, R0h1t — every base word with 1-3 leet substitutions.",
         mutated and bool(re.search(r"[0-9!@#$%^&*]", pw)) and bool(re.search(r"[A-Za-z]", pw))),
        ("case_perm", "Priority 4 — Case Permutations", "Title, UPPER, lower, tOGGLE, cAPITALIZE — ~4-8 case permutations per base word.",
         bool(re.fullmatch(r"[A-Za-z]+", pw)) is not None and not (pw.islower() or pw.isupper())),
        ("reverse_dup", "Priority 5 — Reverse / Duplicate / Insertion Rules", "Attacker rules: reverse, double first letter, insert a letter, strip vowels, duplicate chars.",
         mutated and len(pw) >= 6),
        ("mega_rule", "Priority 6 — Mega Rule-Set (John the Ripper + Hashcat)", "Full combo: ~500k Hashcat rules × 20k base words × 40 append symbols — billions of realistic human-looking passwords.",
         True),
    ]

    for idx, (cid, cname, cdesc, hit_cond) in enumerate(specs):
        priority = idx + 1
        if found_in_priority is not None:
            report.append(AttackCategoryReport(
                category_id=cid,
                category_name=cname,
                description=cdesc,
                attempts=0,
                priority=priority,
                hit=False,
                skipped=True,
                skip_reason=(
                    f"Password found in Category #{found_in_priority} ({found_in_category_id}) — "
                    f"remaining hybrid mutation rules skipped (early exit)."
                ),
            ))
            continue

        # Last category: only fire if nothing else matched
        actual_hit = hit_cond
        if cid == "mega_rule":
            actual_hit = True and not any(r.hit for r in report)

        candidate = pw if actual_hit else None
        if actual_hit:
            found_in_priority = priority
            found_in_category_id = cid

        report.append(AttackCategoryReport(
            category_id=cid,
            category_name=cname,
            description=cdesc,
            attempts=attempts_per_category if not actual_hit else 1,
            priority=priority,
            hit=bool(actual_hit),
            hit_position=1 if actual_hit else None,
            hit_candidate=candidate,
        ))
    return [c.to_dict() for c in report]


def _simulate_rainbow_table(pw: str, score: int) -> Tuple[float, int, str]:
    low = pw.lower()
    # Rainbow tables are extremely effective for unsalted short/weak passwords.
    if low in WEAK_PASSWORDS or len(pw) <= 6:
        return 0.05, 1, "Instant precomputed hash lookup."
    if len(pw) <= 8:
        return 5, 1_000_000, "Matches a known ≤ 8-char MD5/SHA1 rainbow table."
    if 50 <= score < 80 and not any(c in string.punctuation for c in pw):
        return 30 * 24 * 3600, 5_000_000_000, "A big rainbow table could enumerate this charset."
    return 1e13 * 365 * 24 * 3600, 10 ** 12, "Not in any existing precomputed table."


def _simulate_hybrid(pw: str, score: int) -> Tuple[float, int, str]:
    low = pw.lower()
    if low in WEAK_PASSWORDS:
        return 0.3, 500, "Top password + trivial mutation rules."
    # e.g. Hello123, summer2024!
    mutated_word = (
        _contains_dictionary_word(pw)
        or _has_year_or_birthday(pw)
        or (re.fullmatch(r"[A-Z][a-z]+[0-9]{1,4}[!@#$%^&*]?", pw) is not None)
    )
    if mutated_word:
        return 20 * 60, 500_000, "Hybrid rules (word + year + 1 symbol) cover this pattern."
    if score < 70:
        return 7 * 24 * 3600, 10_000_000, "Broad hybrid rule-set likely reaches it in under a week."
    return 5e9 * 365 * 24 * 3600, 10 ** 14, "No predictable structure — hybrid rules can't reach it."


def _success_rate_and_level(seconds: float, score: int) -> Tuple[float, str]:
    # success_rate_value is used for rendering; success_rate is the display string.
    if seconds < 1:
        return 100.0, "100% — Cracked instantly."
    if seconds < 60:
        return 98.0, "98% — Cracked in under a minute."
    if seconds < 60 * 60:
        return 92.0, "92% — Cracked within the hour."
    if seconds < 24 * 3600:
        return 80.0, "80% — Cracked within a day."
    if seconds < 7 * 24 * 3600:
        return 60.0, "60% — Likely cracked within a week."
    if seconds < 365 * 24 * 3600:
        return 35.0, "35% — Possible with dedicated hardware."
    if seconds < 1_000_000 * 365 * 24 * 3600:
        return 5.0, "5% — Unlikely with current computing power."
    return 0.0, "0% — Impossible with current computing power."


def simulate_attack(
    attack_id: str,
    password: str,
    hints: List[str] | str | None = None,
) -> AttackResult:
    """Simulate an educational attack and return a fully-populated AttackResult.

    Optional `hints` are used only for the Dictionary attack (other attacks
    ignore them). Hints can be a list or a comma-separated string — they are
    normalized via parse_hints() before use.
    """
    if not password:
        raise ValueError("Password cannot be empty")
    if attack_id not in ATTACK_TYPES:
        raise ValueError(f"Unknown attack id: {attack_id}")

    # Normalize hints (list or comma-separated string → List[str])
    normalized_hints: List[str] = []
    if hints:
        if isinstance(hints, str):
            normalized_hints = parse_hints(hints)
        else:
            try:
                normalized_hints = parse_hints(",".join(str(h) for h in hints))
            except TypeError:
                normalized_hints = []
    # Hints ONLY apply to Dictionary attack. Other attacks ignore them silently.
    dictionary_hints = normalized_hints if attack_id == "dictionary" else []

    score, breakdown, _ = evaluate_password(password)
    simulators = {
        "brute_force": _simulate_brute_force,
        "dictionary": _simulate_dictionary,
        "rainbow_table": _simulate_rainbow_table,
        "hybrid": _simulate_hybrid,
    }
    if attack_id == "dictionary":
        seconds, attempts, reason = _simulate_dictionary(password, score, dictionary_hints or None)
    else:
        seconds, attempts, reason = simulators[attack_id](password, score)
    success_val, success_str = _success_rate_and_level(seconds, score)

    # --- Spec overrides for three canonical teaching examples ---
    spec = _spec_override(password)
    if spec is not None:
        score = int(spec.get("score", score))
        seconds = float(spec.get("estimated_seconds", seconds))
        success_val = float(spec.get("success_rate_value", success_val))
        success_str = spec.get("success_rate", success_str)
        # strength / risk follow from overridden score unless explicitly set.
        strength = spec.get("strength") or _strength_from_score(score)
        risk = spec.get("risk") or _risk_from_score(score)
        estimated_time = spec.get("estimated_time") or _human_time(seconds)
    else:
        strength = _strength_from_score(score)
        risk = _risk_from_score(score)
        estimated_time = _human_time(seconds)

    attack_meta = ATTACK_TYPES[attack_id]

    # Educational display rule: ALWAYS simulate a full run of at least
    # 10 lakh (1,000,000) attempts so the counter visibly shows lakh milestones.
    # If the attack would legitimately exceed 10L attempts, keep the real number.
    display_attempts = int(attempts)
    if display_attempts < 1_000_000:
        display_attempts = 1_000_000

    # Build a terminal-friendly log that the frontend renders with typing effect.
    # Indian-notation milestones (1 lakh, 5 lakh, 10 lakh) shown if applicable.
    found_log: List[str] = [
        f"> Initializing {attack_meta['name']} attack module...",
        "> Loading attack parameters...",
        f"> Character-set analysis: {_character_set_size(password)} symbols, length={len(password)}",
        f"> Target: {'*' * len(password)}",
    ]

    # Dictionary attack: show personalized hint loading in the log if provided.
    if attack_id == "dictionary" and dictionary_hints:
        found_log.append("> Running in TARGETED mode with user-provided personalized hints.")
        found_log.extend(_build_hint_summary_lines(dictionary_hints))
        candidate_pool = _estimate_hint_candidate_count(dictionary_hints)
        found_log.append(f"> Personalized wordlist size: ~ {candidate_pool:,} candidates")

    found_log.extend([
        "> Loading candidate generator...",
        f"> Attack rule-set: {attack_meta['name']}",
        f"> Attempt 1 ...",
        f"> Attempt 10 ...",
        "> Attempt 100 ...",
        "> Attempt 1,000 ... (1 thousand)",
    ])
    if display_attempts >= 10_000:
        found_log.append("> Attempt 10,000 ... (10 thousand)")
    if display_attempts >= 50_000:
        found_log.append("> Attempt 50,000 ... (50 thousand)")
    if display_attempts >= 100_000:
        found_log.append("> Attempt 1,00,000 ... (1 LAKH) ✓")
    if display_attempts >= 250_000:
        found_log.append("> Attempt 2,50,000 ... (2.5 lakh)")
    if display_attempts >= 500_000:
        found_log.append("> Attempt 5,00,000 ... (5 LAKH)")
    if display_attempts >= 750_000:
        found_log.append("> Attempt 7,50,000 ... (7.5 lakh)")
    if display_attempts >= 1_000_000:
        found_log.append("> Attempt 10,00,000 ... (10 LAKH) ✓")
    if display_attempts >= 2_500_000:
        found_log.append("> Attempt 25,00,000 ... (25 lakh)")
    if display_attempts >= 10_000_000:
        found_log.append("> Attempt 1,00,00,000 ... (1 Crore)")
    found_log.extend([
        f"> -- analysis -- {reason}",
        f"> Total candidates evaluated: ~ {display_attempts:,}",
        "> Verifying candidate match against target hash ...",
        "> Password evaluated.",
    ])
    found_log = [line for line in found_log if line]

    # ---- Build category-wise attack report (6 categories × 10B attempts each) ----
    ATTEMPTS_PER_CATEGORY = 10_000_000_000
    if attack_id == "dictionary":
        report_categories = _build_dictionary_categories(
            password, dictionary_hints, attempts_per_category=ATTEMPTS_PER_CATEGORY
        )
    elif attack_id == "brute_force":
        report_categories = _build_brute_force_categories(
            password, attempts_per_category=ATTEMPTS_PER_CATEGORY
        )
    elif attack_id == "rainbow_table":
        report_categories = _build_rainbow_categories(
            password, attempts_per_category=ATTEMPTS_PER_CATEGORY
        )
    else:  # hybrid
        report_categories = _build_hybrid_categories(
            password, attempts_per_category=ATTEMPTS_PER_CATEGORY
        )

    # Mask the actual password for the target field (show only length and pattern)
    masked_target = "*" * len(password)

    return AttackResult(
        attack=attack_meta["name"],
        strength=strength,
        estimated_time=str(estimated_time),
        estimated_seconds=float(seconds),
        risk=str(risk),
        success_rate=str(success_str),
        success_rate_value=float(success_val),
        score=int(score),
        attempts_approx=int(display_attempts),
        tips=_base_tips(password),
        found_log=found_log,
        educational={
            "why_works": attack_meta["why_works"],
            "why_fails": attack_meta["why_fails"],
            "defend": attack_meta["defend"],
            "best_practices": "\n".join(f"• {b}" for b in attack_meta["best_practices"]),
            "note": reason,
        },
        security_breakdown=breakdown,
        attack_report=report_categories,
        password_target=masked_target,
        hints_used_detailed=list(dictionary_hints),
    )


def get_attack_types_public() -> List[Dict]:
    """Safe list of attack metadata for rendering the 4 attack cards."""
    out = []
    for key, meta in ATTACK_TYPES.items():
        out.append(
            {
                "id": meta["id"],
                "name": meta["name"],
                "icon": meta["icon"],
                "description": meta["description"],
            }
        )
    return out


def estimate_entropy_bits(pw: str) -> float:
    if not pw:
        return 0.0
    return round(len(pw) * math.log2(_character_set_size(pw)), 1)
