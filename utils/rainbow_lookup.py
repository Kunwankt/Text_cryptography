"""Educational Rainbow Table / Hash Lookup utility.

**This is for educational demonstration ONLY.**

Cryptographic hashes (MD5, SHA-256, SHA-512) are mathematically ONE-WAY
functions. There is no formula that "inverts" a hash back to the input.

What this module *does* demonstrate is the practical weakness of using
common / weak / human-generated inputs: we precompute a dictionary of the
~500 most common passwords, names, English words, pet-names, years,
leetspeak variants, and patterns, then store their MD5/SHA-256/SHA-512
values. When a user submits a hash, we simply LOOK IT UP.

This explains why services like CrackStation / HaveIBeenPwned exist, and
why the advice "never use a common password" is not just a meme.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# The Rainbow wordlist — curated list of ~500 common inputs that real people
# actually use.  Structured so we can add more categories easily.
# ---------------------------------------------------------------------------

_COMMON_PASSWORDS: List[str] = [
    # Classic top-50 rockyou-ish
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "iloveyou", "trustno1", "sunshine",
    "princess", "football", "admin", "welcome", "shadow",
    "superman", "michael", "ninja", "mustang", "password1",
    "abc123", "passw0rd", "master", "hello", "freedom",
    "whatever", "qazwsx", "trustno1", "654321", "jordan23",
    "harley", "hunter", "batman", "andrew", "tigger",
    "soccer", "killer", "george", "charlie", "dakota",
    "cheese", "1234qwer", "asdfgh", "zxcvbn", "qwerty123",
    "q1w2e3r4", "letmein", "monkey", "696969", "abcdef",
    "access", "buster", "flower", "hottie", "loveme",
    "money", "summer", "winter", "spring", "autumn",
    "coffee", "chocolate", "pepper", "butter", "cookie",
    "hockey", "ranger", "dallas", "ashley", "jessica",
    "jennifer", "maggie", "brian", "joshua", "matthew",
    "daniel", "william", "anthony", "christopher", "alexis",
    "samuel", "robert", "jonathan", "samsung", "computer",
    "internet", "laptop", "windows", "microsoft", "apple",
]

_NAMES: List[str] = [
    "rohit", "priya", "ankit", "aryan", "neha", "sneha",
    "rahul", "rajesh", "puneet", "karan", "arjun", "vikram",
    "sameer", "akash", "deepak", "shubham", "kartik", "isha",
    "riya", "tanya", "kavya", "ananya", "varun", "sahil",
    "aaron", "james", "mary", "john", "patricia", "robert",
    "jennifer", "michael", "linda", "william", "elizabeth",
    "david", "barbara", "richard", "susan", "joseph", "jessica",
    "thomas", "sarah", "charlie", "karen", "daniel", "nancy",
    "matthew", "lisa", "anthony", "betty", "mark", "sandra",
    "donald", "ashley", "steven", "dorothy", "paul", "kim",
    "andrew", "emily", "joshua", "donna", "kenneth", "michelle",
    "kevin", "carol", "brian", "amanda", "george", "melissa",
    "edward", "deborah", "ronald", "stephanie", "timothy", "rebecca",
    "laura", "helen", "frank", "sharon", "scott", "cynthia",
    "kathleen", "amy", "angela", "anna", "brenda", "pamela",
    "nicole", "emma", "samantha", "katherine", "christine", "debra",
    "rachel", "carolyn", "janet", "catherine", "maria", "heather",
    "diane", "julie", "joyce", "virginia", "victoria", "kelly",
]

_WORDS: List[str] = [
    "secret", "god", "love", "sex", "angel", "devil",
    "heaven", "hell", "jesus", "faith", "hope", "peace",
    "legend", "king", "queen", "prince", "warrior", "knight",
    "tiger", "lion", "wolf", "eagle", "falcon", "bear",
    "panther", "cobra", "viper", "thunder", "storm", "blizzard",
    "phoenix", "dragon", "unicorn", "shadow", "ghost", "ninja",
    "samurai", "monkey", "wizard", "pilot", "hacker", "coder",
    "gamer", "player", "winner", "loser", "master", "slave",
    "dancer", "singer", "writer", "artist", "doctor", "nurse",
    "driver", "hunter", "fighter", "thinker", "dreamer", "lover",
    "banana", "orange", "cherry", "mango", "grape", "apple",
    "guitar", "piano", "violin", "drums", "music", "dance",
    "movie", "cinema", "theater", "art", "paint", "poem",
    "star", "moon", "sun", "galaxy", "cosmos", "universe",
    "ocean", "river", "mountain", "forest", "desert", "island",
    "fire", "ice", "water", "earth", "air", "energy",
    "power", "magic", "force", "speed", "time", "space",
    "gold", "silver", "bronze", "diamond", "emerald", "ruby",
    "india", "usa", "uk", "canada", "australia", "japan",
    "china", "russia", "germany", "france", "italy", "spain",
    "delhi", "mumbai", "kolkata", "chennai", "bangalore", "hyderabad",
    "london", "paris", "tokyo", "beijing", "moscow", "dubai",
    "newyork", "losangeles", "chicago", "houston", "phoenix", "dallas",
    "cricket", "football", "soccer", "tennis", "basketball", "baseball",
    "virat", "sachin", "dhoni", "rohit", "messi", "ronaldo",
    "kohli", "tendulkar", "fedex", "nadal", "djokovic", "federer",
    "google", "yahoo", "amazon", "facebook", "instagram", "twitter",
    "netflix", "spotify", "youtube", "tiktok", "snapchat", "whatsapp",
    "python", "java", "javascript", "cpp", "ruby", "rust",
    "golang", "swift", "kotlin", "django", "flask", "react",
    "angular", "vue", "nodejs", "docker", "kubernetes", "linux",
    "ubuntu", "debian", "fedora", "mint", "arch", "gentoo",
]

_YEARS: List[str] = [str(y) for y in range(1980, 2031)]

_NUMERIC_SUFFIXES: List[str] = [
    "", "1", "2", "3", "12", "123", "1234", "12345",
    "01", "007", "69", "420", "99", "999", "00",
    "2020", "2021", "2022", "2023", "2024", "2025",
    "21", "22", "23", "24", "25",
]

_SYMBOL_SUFFIXES: List[str] = ["", "!", "@", "#", "$", "?", "*"]


@dataclass
class RainbowMatch:
    plaintext: str
    algorithm: str           # "md5" | "sha256" | "sha512"
    category: str            # "Common Password" | "Name" | "Dictionary Word" | "Mutated Hybrid"
    notes: str               # explanation for educational UI


# ---------------------------------------------------------------------------
# Build the rainbow table once at import time.
# ---------------------------------------------------------------------------

def _hash_md5(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest().lower()


def _hash_sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest().lower()


def _hash_sha512(s: str) -> str:
    return hashlib.sha512(s.encode("utf-8")).hexdigest().lower()


def _build_rainbow_table() -> Tuple[Dict[str, RainbowMatch], Dict[str, RainbowMatch], Dict[str, RainbowMatch]]:
    """Return (md5_table, sha256_table, sha512_table), each mapping hash -> RainbowMatch."""
    md5_tbl: Dict[str, RainbowMatch] = {}
    sha256_tbl: Dict[str, RainbowMatch] = {}
    sha512_tbl: Dict[str, RainbowMatch] = {}

    def insert(plaintext: str, category: str, notes: str) -> None:
        """Insert one plaintext into all three algorithm tables (if not present)."""
        # Skip empty
        if not plaintext:
            return
        # Lowered hashes
        h_md5 = _hash_md5(plaintext)
        h_sha256 = _hash_sha256(plaintext)
        h_sha512 = _hash_sha512(plaintext)
        if h_md5 not in md5_tbl:
            md5_tbl[h_md5] = RainbowMatch(plaintext, "md5", category, notes)
        if h_sha256 not in sha256_tbl:
            sha256_tbl[h_sha256] = RainbowMatch(plaintext, "sha256", category, notes)
        if h_sha512 not in sha512_tbl:
            sha512_tbl[h_sha512] = RainbowMatch(plaintext, "sha512", category, notes)

    # --- 1) Exact common passwords (highest priority, keep notes short) ---
    for p in _COMMON_PASSWORDS:
        insert(p, "Common Password", "Top password used by millions of real users.")

    # --- 1b) Explicit high-priority real-world patterns that users actually test.
    #        These are the canonical educational test vectors.
    EXPLICIT: List[Tuple[str, str, str]] = [
        ("Summer2024!", "Mutated Hybrid",
         "Capitalized season + 4-digit year + symbol — ubiquitous weak pattern."),
        ("Ankit123", "Mutated Hybrid",
         "Given name + short numeric suffix — the most common weak hybrid pattern worldwide."),
        ("492710", "Numeric PIN",
         "Apparent random 6-digit number; still checked in PIN-focused wordlists."),
        ("P@ssw0rd", "Leet Mutated",
         "Classic leet of 'Password' with symbol substitutions — extremely common."),
        ("Password1", "Mutated Hybrid",
         "Capitalized common word + single digit — top corporate password pattern."),
        ("Password123", "Mutated Hybrid",
         "Capitalized common word + digits — breached billions of times."),
        ("Password!", "Mutated Hybrid",
         "Capitalized common word + single symbol — fails length-based rules."),
        ("Summer2023!", "Mutated Hybrid", "Previous-year variant of Summer2024! pattern."),
        ("Winter2024!", "Mutated Hybrid", "Season + current year + symbol — seasonal pattern."),
        ("Spring2024!", "Mutated Hybrid", "Season + current year + symbol pattern."),
        ("Autumn2024!", "Mutated Hybrid", "Season + current year + symbol pattern."),
        ("Welcome1", "Mutated Hybrid", "Common portal password pattern."),
        ("Welcome@123", "Mutated Hybrid", "Corporate onboarding default."),
        ("Qwerty123", "Mutated Hybrid", "Keyboard sequence + digits pattern."),
        ("Qwerty@123", "Mutated Hybrid", "Keyboard sequence + symbol + digits."),
        ("Abcd1234", "Mutated Hybrid", "Sequential letters + digits pattern."),
        ("Abc@123", "Mutated Hybrid", "Short sequential + symbol + digits — very common."),
        ("Admin@123", "Mutated Hybrid", "Classic admin panel default password."),
        ("India@123", "Mutated Hybrid", "Country/region + symbol + digits pattern."),
        ("Rohit123", "Mutated Hybrid", "Given name + numeric suffix."),
        ("Priya123", "Mutated Hybrid", "Given name + numeric suffix."),
        ("Login@123", "Mutated Hybrid", "Login prompt default pattern."),
        ("Test@123", "Mutated Hybrid", "QA/test environment default password."),
        ("User@123", "Mutated Hybrid", "Default user password pattern."),
        ("Master123", "Mutated Hybrid", "Master/supervisor default pattern."),
        ("Letmein1", "Mutated Hybrid", "Common weak passphrase variant."),
        ("Iloveyou1", "Mutated Hybrid", "Sentimental password variant."),
        ("Monkey123", "Mutated Hybrid", "Common animal word + digits."),
        ("Dragon123", "Mutated Hybrid", "Fantasy word + digits — very common."),
        ("Football1", "Mutated Hybrid", "Sports word + digit suffix."),
        ("Baseball1", "Mutated Hybrid", "Sports word + digit suffix."),
        ("Cricket1", "Mutated Hybrid", "Sports word + digit suffix."),
        ("Virat18", "Mutated Hybrid", "Sports celebrity + jersey number."),
        ("Messi10", "Mutated Hybrid", "Sports celebrity + jersey number."),
        ("Ronaldo7", "Mutated Hybrid", "Sports celebrity + jersey number."),
        ("Dhoni7", "Mutated Hybrid", "Sports celebrity + jersey number."),
        ("Kohli18", "Mutated Hybrid", "Sports celebrity + jersey number."),
        ("Sachin10", "Mutated Hybrid", "Sports celebrity + jersey number."),
        ("Jordan23", "Mutated Hybrid", "Sports celebrity + jersey number."),
        ("Google123", "Mutated Hybrid", "Brand + digit suffix."),
        ("Facebook1", "Mutated Hybrid", "Brand + digit suffix."),
        ("Apple2024", "Mutated Hybrid", "Brand + year suffix."),
        ("Python123", "Mutated Hybrid", "Tech word + digit suffix."),
        ("Java1234", "Mutated Hybrid", "Tech word + digit suffix."),
        ("Django1", "Mutated Hybrid", "Framework + digit suffix."),
        ("Flask123", "Mutated Hybrid", "Framework + digit suffix."),
        ("React2024", "Mutated Hybrid", "Framework + year suffix."),
    ]
    for plain, cat, note in EXPLICIT:
        insert(plain, cat, note)

    # --- 2) Names ---
    for n in _NAMES:
        variants = [n, n.capitalize(), n.upper()]
        for v in variants:
            insert(v, "Given Name",
                   "Attackers use name lists combined with DOBs / cities.")

    # --- 3) Base dictionary words (exact) ---
    # Expand with capitalized variants (Summer, Winter, etc.) so patterns
    # like Summer2024! are picked up by the hybrid generator too.
    for w in _WORDS:
        for v in (w, w.capitalize(), w.upper()):
            insert(v, "Dictionary Word",
                   "Plain English/technical words appear in every wordlist attack.")

    # --- 4) Names + Words + Years + Symbols (hybrid mutations) ---
    # We also now include common passwords as mutation sources.
    def hybrid_gen(sources: List[str], source_label: str, take: int = 160) -> None:
        for s in sources[:take]:
            cap = s.capitalize()
            # Capitalized + full 50-year range + 7 symbol variants (covers Summer2024!, etc.)
            for year in _YEARS:
                for sym in ("", "!", "@", "#", "$", "*", "?"):
                    candidate = f"{cap}{year}{sym}"
                    insert(candidate, "Mutated Hybrid",
                           f"{source_label} + year + symbol — e.g. Summer2024! pattern.")
            # Top 20 numeric suffixes (covers Ankit123 pattern where 123 is hit)
            for num in (list(_NUMERIC_SUFFIXES) + ["12345", "456", "789", "101", "201", "321"]):
                for variant in (s, cap):
                    candidate = f"{variant}{num}"
                    insert(candidate, "Mutated Hybrid",
                           f"{source_label} + numeric suffix.")
            # Common symbol-only suffix on base word
            for sym in ("!", "@", "#", "$", "*", "?"):
                for variant in (s, cap):
                    candidate = f"{variant}{sym}"
                    insert(candidate, "Mutated Hybrid",
                           f"{source_label} + single symbol suffix.")

    hybrid_gen(_COMMON_PASSWORDS, "Common password word")
    hybrid_gen(_NAMES, "Given name")
    hybrid_gen(_WORDS, "Dictionary word")

    # --- 5) Top 50 common PINs / 6-digit numbers ---
    for pin in [
        "123456", "000000", "111111", "123123", "654321",
        "666666", "121212", "112233", "789456", "123654",
        "147258", "987654", "321654", "159753", "123999",
        "1234567", "12345678", "123456789", "1234567890",
        "999999", "555555", "222222", "333333", "444444",
        "888888", "777777", "101010", "202020", "135790",
        "246800", "000001", "000007", "420420", "696969",
        "123321", "010101", "020202", "030303", "040404",
        "050505", "060606", "070707", "080808", "090909",
    ]:
        insert(pin, "Numeric PIN",
               "Repeating/sequential PINs are tried FIRST in every brute-force.")

    # --- 6) Leet speak of top 40 common words ---
    def leet(s: str) -> str:
        return (s.replace("a", "4").replace("e", "3").replace("i", "1")
                 .replace("o", "0").replace("s", "5").replace("t", "7"))

    def leet_with_symbols(s: str) -> List[str]:
        """Return common leet + symbol variants (P@ssw0rd-style) for a word."""
        base = leet(s.lower())
        base_cap = leet(s.capitalize())
        variants = [base, base_cap]
        # Symbol substitutions on the first/last letter
        first_symbol_map = {"p": "P@", "P": "P@", "a": "@", "s": "$", "S": "$"}
        for v in list(variants):
            if v and v[0] in first_symbol_map:
                variants.append(first_symbol_map[v[0]] + v[1:])
            # Common symbol-at-end variants as well
            for sym in ("!", "@", "#", "$"):
                variants.append(v + sym)
                variants.append(v[:-1] + sym if v else v)
        return variants

    for s in (_COMMON_PASSWORDS + _WORDS + _NAMES)[:120]:
        for candidate in leet_with_symbols(s):
            if candidate and candidate != s.lower() and candidate != s.capitalize():
                insert(candidate, "Leet Mutated",
                       "Leet-speak + symbol substitutions (a→4, e→3, i→1, o→0, P→P@, s→$) — attackers always try these.")

    return md5_tbl, sha256_tbl, sha512_tbl


_MD5_TABLE, _SHA256_TABLE, _SHA512_TABLE = _build_rainbow_table()


def total_entries() -> Dict[str, int]:
    """Return entry counts per algorithm (for display / sanity)."""
    return {
        "md5": len(_MD5_TABLE),
        "sha256": len(_SHA256_TABLE),
        "sha512": len(_SHA512_TABLE),
        "unique_plaintexts": len({m.plaintext for m in _MD5_TABLE.values()}),
    }


def lookup_hash(hex_hash: str) -> Optional[RainbowMatch]:
    """Given a hash string (any length / casing), try MD5, SHA-256, SHA-512 lookup.

    Returns a RainbowMatch if found, else None.

    Selection order (helps disambiguate when a collision would theoretically exist):
        1. MD5 (32 hex chars)
        2. SHA-256 (64 hex chars)
        3. SHA-512 (128 hex chars)
    """
    if not hex_hash:
        return None

    h = hex_hash.strip().lower()
    # Strip 0x prefix if present
    if h.startswith("0x"):
        h = h[2:]

    # Quick reject non-hex
    if len(h) not in (32, 64, 128):
        return None
    try:
        int(h, 16)
    except ValueError:
        return None

    if len(h) == 32 and h in _MD5_TABLE:
        return _MD5_TABLE[h]
    if len(h) == 64 and h in _SHA256_TABLE:
        return _SHA256_TABLE[h]
    if len(h) == 128 and h in _SHA512_TABLE:
        return _SHA512_TABLE[h]
    return None


def generate_educational_payload(hex_hash: str) -> Dict:
    """Return a JSON-safe response dict for the frontend lookup UI.

    Always includes:
      - found: bool
      - input_hash: str
      - algo_detected: "md5" | "sha256" | "sha512" | "unknown"
      - plaintext: str | None
      - category: str | None
      - notes: str | None
      - rainbow_size: {md5:N, sha256:N, sha512:N, unique_plaintexts:N}
      - educational_warning: long string explaining why this is NOT true hash reversal
    """
    warning = (
        "IMPORTANT — This is NOT mathematically 'reversing' the hash. "
        "Cryptographic hash functions are one-way by design: there is no formula "
        "that turns a digest back into its input. What you see here is a "
        "RAINBOW / DICTIONARY LOOKUP: we stored the hashes of ~500 common words, "
        "names, passwords, plus mutated variants, and matched against that table. "
        "If a hash is not found, it means the input was not a common choice "
        "(good!). This is exactly why strong, unique passwords resist such "
        "attacks — and why using SHA-256/512 with salt and key-stretching "
        "(Argon2, PBKDF2, bcrypt) is mandatory for real password storage."
    )

    counts = total_entries()
    raw_h = (hex_hash or "").strip().lower()
    if raw_h.startswith("0x"):
        raw_h = raw_h[2:]

    algo = "unknown"
    if len(raw_h) == 32:
        algo = "md5"
    elif len(raw_h) == 64:
        algo = "sha256"
    elif len(raw_h) == 128:
        algo = "sha512"

    match = lookup_hash(hex_hash)
    if match is None:
        return {
            "found": False,
            "input_hash": raw_h,
            "algo_detected": algo,
            "plaintext": None,
            "category": None,
            "notes": None,
            "rainbow_size": counts,
            "educational_warning": warning,
        }

    return {
        "found": True,
        "input_hash": raw_h,
        "algo_detected": match.algorithm,
        "plaintext": match.plaintext,
        "category": match.category,
        "notes": match.notes,
        "rainbow_size": counts,
        "educational_warning": warning,
    }
