"""Cryptographic cipher engines used EXCLUSIVELY for the educational Cryptography Games module.

All ciphers here are classic, intentionally weak / educational-only (Caesar, Atbash,
Vigenère, simple monoalphabetic substitution, simple columnar transposition demo, etc.).

They are used to generate game levels, hints, explanations and answer keys. This module
does NOT touch any real user secrets — it's a pure helper library that produces
predictable, well-known, demo ciphertexts.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import random
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Alphabet & basic helpers
# ---------------------------------------------------------------------------
ALPHA_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHA_LOWER = ALPHA_UPPER.lower()
ENGLISH_COMMON = "ETAOINSHRDLCUMWFGYPBVKJXQZ"  # descending freq order

COMMON_DICT_WORDS: Tuple[str, ...] = (
    "HELLO", "WORLD", "SECRET", "MESSAGE", "ATTACK", "ENCRYPT", "CIPHER",
    "PASSWORD", "CRYPTOGRAPHY", "NETWORK", "SECURITY", "ALGORITHM", "PYTHON",
    "FLASK", "COMPUTER", "KEYBOARD", "HACKER", "SHIELD", "TERMINAL", "CAESAR",
    "VIGENERE", "SUBSTITUTE", "RAINBOW", "PHISHING", "INTRUSION", "BINARY",
    "SYSTEM", "WINDOW", "LIBRARY", "MALWARE", "FIREWALL", "BACKDOOR",
    "ANONYMOUS", "SATELLITE", "DATABASE", "HAMMER", "OCTOPUS", "LIBERTY",
    "PARADOX", "EMBASSY", "MIDNIGHT", "DRAGONFLY", "PHOENIX", "EMPIRE",
    "VICTORY", "FREEDOM", "HORIZON", "JOURNEY", "MIRROR", "DIAMOND",
)

WEAK_RSA_KEYS_DEMO: Tuple[Dict[str, Any], ...] = (
    {
        "key_label": "4-bit toy n=55",
        "public": dict(n=55, e=3),
        "private_p": 5,
        "private_q": 11,
        "plaintext_demo": 42,
        "hint": "n is so small you can factor it by hand (check divisibility by 3, 5, 7, 11).",
    },
    {
        "key_label": "6-bit toy n=187",
        "public": dict(n=187, e=7),
        "private_p": 11,
        "private_q": 17,
        "plaintext_demo": 23,
        "hint": "Check small primes up to sqrt(n) ≈ 13.7: 2, 3, 5, 7, 11, 13.",
    },
    {
        "key_label": "Shared factor toy n1=221, n2=323",
        "public": dict(n=221, e=5),
        "private_p": 13,
        "private_q": 17,
        "plaintext_demo": 7,
        "hint": "gcd(n1, n2) leaks a prime when two keys share p or q — classic shared-factor attack demo.",
    },
)


# ---------------------------------------------------------------------------
# Caesar cipher
# ---------------------------------------------------------------------------
def caesar_shift(ch: str, shift: int, reverse: bool = False) -> str:
    if not ch.isalpha():
        return ch
    shift = shift % 26
    if reverse:
        shift = (-shift) % 26
    base = ord('A') if ch.isupper() else ord('a')
    return chr((ord(ch) - base + shift) % 26 + base)


def caesar_encrypt(plaintext: str, shift: int) -> str:
    return "".join(caesar_shift(c, shift, False) for c in plaintext)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    return "".join(caesar_shift(c, shift, True) for c in ciphertext)


# ---------------------------------------------------------------------------
# Atbash
# ---------------------------------------------------------------------------
def atbash_letter(ch: str) -> str:
    if not ch.isalpha():
        return ch
    base = ord('A') if ch.isupper() else ord('a')
    return chr(base + (25 - (ord(ch) - base)))


def atbash_encrypt(plaintext: str) -> str:
    return "".join(atbash_letter(c) for c in plaintext)


atbash_decrypt = atbash_encrypt


# ---------------------------------------------------------------------------
# Vigenère
# ---------------------------------------------------------------------------
def vigenere_encrypt(plaintext: str, keyword: str) -> str:
    keyword = [ord(c.upper()) - ord('A') for c in keyword if c.isalpha()]
    if not keyword:
        return plaintext
    out, i = [], 0
    for c in plaintext:
        if c.isalpha():
            out.append(caesar_shift(c, keyword[i % len(keyword)], False))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def vigenere_decrypt(ciphertext: str, keyword: str) -> str:
    keyword = [ord(c.upper()) - ord('A') for c in keyword if c.isalpha()]
    if not keyword:
        return ciphertext
    out, i = [], 0
    for c in ciphertext:
        if c.isalpha():
            out.append(caesar_shift(c, keyword[i % len(keyword)], True))
            i += 1
        else:
            out.append(c)
    return "".join(out)


# ---------------------------------------------------------------------------
# Monoalphabetic substitution (random permutation keyed by seed)
# ---------------------------------------------------------------------------
def monoalphabetic_key(seed: int = 1) -> Dict[str, str]:
    rng = random.Random(seed)
    shuffled = list(ALPHA_UPPER)
    rng.shuffle(shuffled)
    return dict(zip(ALPHA_UPPER, shuffled))


def monoalphabetic_encrypt(plaintext: str, key: Dict[str, str]) -> str:
    inv_map = {c.lower(): key[c].lower() for c in key}
    out = []
    for c in plaintext:
        if c.upper() in key:
            out.append(key[c.upper()] if c.isupper() else inv_map[c])
        else:
            out.append(c)
    return "".join(out)


def monoalphabetic_decrypt(ciphertext: str, key: Dict[str, str]) -> str:
    rev = {v: k for k, v in key.items()}
    rev_lower = {v.lower(): k.lower() for k, v in key.items()}
    out = []
    for c in ciphertext:
        if c.upper() in rev:
            out.append(rev[c.upper()] if c.isupper() else rev_lower[c])
        else:
            out.append(c)
    return "".join(out)


# ---------------------------------------------------------------------------
# Simple columnar transposition (demo — for puzzle / crack levels)
# ---------------------------------------------------------------------------
def columnar_encrypt(plaintext: str, key: str) -> str:
    """Very simple columnar transposition used ONLY in educational puzzles."""
    keyword = [c.upper() for c in key if c.isalpha()]
    if not keyword:
        return plaintext
    order = sorted(range(len(keyword)), key=lambda i: keyword[i])
    cleaned = re.sub(r"\s+", "", plaintext)
    cols = len(order)
    rows = (len(cleaned) + cols - 1) // cols
    padded = cleaned.ljust(rows * cols, "X")
    grid = [padded[i:i + cols] for i in range(0, len(padded), cols)]
    return "".join(grid[r][order[c]] for c in range(cols) for r in range(rows))


# ---------------------------------------------------------------------------
# SHA-1 / MD5 / SHA-256 small known preimage catalog (EDUCATIONAL ONLY)
# Used for "Hash Detective" game — a few toy strings, never real user data.
# ---------------------------------------------------------------------------
HASH_PREIMAGES: Tuple[Tuple[str, str], ...] = (
    ("123456", "common numeric password"),
    ("password", "most common dictionary password"),
    ("admin", "default admin password"),
    ("qwerty", "keyboard sequence"),
    ("letmein", "classic weak password"),
    ("welcome", "default welcome phrase"),
    ("monkey", "common animal password"),
    ("dragon", "common animal password"),
    ("master", "common master password"),
    ("football", "common sports password"),
    ("iloveyou", "common phrase password"),
    ("sunshine", "common phrase password"),
    ("princess", "common password"),
    ("abc123", "common weak pattern"),
    ("HelloWorld", "common programmer greeting"),
    ("Summer2024", "hybrid seasonal pattern"),
    ("Hello", "simple greeting"),
    ("Crypto", "simple crypto word"),
)


def precompute_hash_catalog() -> Dict[str, Dict[str, str]]:
    """Build a tiny lookup table used for Hash Detective challenges."""
    table: Dict[str, Dict[str, str]] = {}
    for plain, note in HASH_PREIMAGES:
        for algo in ("md5", "sha1", "sha256"):
            h = hashlib.new(algo)
            h.update(plain.encode("utf-8"))
            table[h.hexdigest()] = {
                "plaintext": plain,
                "algorithm": algo,
                "note": note,
            }
    return table


# ---------------------------------------------------------------------------
# Known vulnerable code snippets (Find the Vulnerability game)
# ---------------------------------------------------------------------------
VULNERABILITY_SNIPPETS: Tuple[Dict[str, Any], ...] = (
    {
        "id": "hardcoded_key",
        "title": "Hardcoded AES Key",
        "language": "python",
        "code": (
            "# AES encryption helper\n"
            "from Crypto.Cipher import AES\n\n"
            "SECRET_KEY = b'dev-secret-key-change-in-production'  # <-- HERE\n\n"
            "def encrypt(plaintext: str) -> bytes:\n"
            "    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)\n"
            "    return cipher.encrypt(pad(plaintext.encode(), 16))\n"
        ),
        "options": [
            "Hardcoded, publicly-known SECRET_KEY — anyone who downloads the source can decrypt all ciphertexts.",
            "The function uses ECB mode (leaks structure) — separate issue but also wrong.",
            "Missing IV — but AES-ECB doesn't take an IV so that's not the bug.",
            "The pad() call is the vulnerability.",
        ],
        "correct_index": 0,
        "severity": "Critical",
        "explanation": (
            "Shipping a secret key inside the source code means it lives in version control, container images, "
            "and employee laptops. It should be injected via env var / secret manager and rotated regularly."
        ),
        "cwe": "CWE-798: Use of Hard-coded Credentials",
    },
    {
        "id": "weak_md5_for_passwords",
        "title": "MD5 Password Hash",
        "language": "python",
        "code": (
            "import hashlib, sqlite3\n\n"
            "def register_user(username: str, password: str):\n"
            "    pw_hash = hashlib.md5(password.encode()).hexdigest()\n"
            "    db = sqlite3.connect('users.db')\n"
            "    db.execute('INSERT INTO users VALUES (?, ?)', (username, pw_hash))\n"
            "    db.commit()\n"
        ),
        "options": [
            "username should be hashed too.",
            "Raw MD5 is fast & unsalted — rainbow tables / GPUs crack the common 10M passwords in seconds.",
            "SQLite is not safe for user stores.",
            "Missing newline before return.",
        ],
        "correct_index": 1,
        "severity": "High",
        "explanation": (
            "For password storage use a slow, salted key-derivation function: Argon2id > bcrypt > PBKDF2-HMAC-SHA256 "
            "(high iteration count, unique per-user salt)."
        ),
        "cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
    },
    {
        "id": "insecure_randomness",
        "title": "Insecure Session Token RNG",
        "language": "python",
        "code": (
            "import random\n\n"
            "def generate_reset_token(user_id: int) -> str:\n"
            "    random.seed(user_id)\n"
            "    token = ''.join(random.choices('abcdef0123456789', k=32))\n"
            "    return token\n"
        ),
        "options": [
            "Using 'random' (Mersenne Twister) + predictable seed = attacker can clone the sequence knowing user_id.",
            "Token length 32 is too short for URLs.",
            "'abcdef0123456789' has no uppercase letters — that's the bug.",
            "Function should return bytes, not str.",
        ],
        "correct_index": 0,
        "severity": "Critical",
        "explanation": (
            "Security tokens must come from a cryptographically secure generator: secrets.token_hex(32) or "
            "secrets.token_urlsafe()."
        ),
        "cwe": "CWE-338: Use of Cryptographically Weak PRNG",
    },
    {
        "id": "aes_ecb_mode",
        "title": "AES-ECB for Structured Data",
        "language": "python",
        "code": (
            "from Crypto.Cipher import AES\n"
            "from Crypto.Util.Padding import pad\n\n"
            "def encrypt_profile(profile_data: bytes, key: bytes) -> bytes:\n"
            "    cipher = AES.new(key, AES.MODE_ECB)\n"
            "    return cipher.encrypt(pad(profile_data, AES.block_size))\n"
        ),
        "options": [
            "Missing padding oracle is the issue.",
            "ECB leaks structure — identical plaintext blocks produce identical ciphertext blocks (Penguin problem).",
            "Key should be passed as hex string.",
            "profile_data must be base64 first.",
        ],
        "correct_index": 1,
        "severity": "Medium",
        "explanation": (
            "Use AES-GCM or AES-CBC + HMAC (or ChaCha20-Poly1305) — authenticated encryption with a unique "
            "nonce per message."
        ),
        "cwe": "CWE-327: Use of ECB Mode",
    },
    {
        "id": "short_rsa_key",
        "title": "512-bit RSA Key",
        "language": "python",
        "code": (
            "from Crypto.PublicKey import RSA\n\n"
            "# Generate a long-lived key for the payment service\n"
            "key = RSA.generate(bits=512)\n"
            "with open('payment_signer.pem', 'wb') as f:\n"
            "    f.write(key.export_key())\n"
        ),
        "options": [
            "RSA.export_key() is deprecated.",
            "512-bit RSA was publicly factored in 1999 — modern cloud clusters factor it in hours. Minimum today is 2048.",
            "Payment keys must be 3DES encrypted on disk.",
            "with should be async.",
        ],
        "correct_index": 1,
        "severity": "High",
        "explanation": (
            "NIST currently recommends RSA-2048 minimum, RSA-3072 for long-lived keys. For new systems prefer "
            "Ed25519 / ECDSA-P256 (much smaller keys for the same security)."
        ),
        "cwe": "CWE-326: Inadequate Encryption Strength",
    },
)


# ---------------------------------------------------------------------------
# Level generators — one bundle per game difficulty
# ---------------------------------------------------------------------------
def _rng_by_difficulty(difficulty: str):
    difficulty = (difficulty or "easy").lower()
    if difficulty in ("hard",):
        return 1.0
    if difficulty in ("medium",):
        return 0.6
    return 0.3


def generate_crack_the_cipher_level(difficulty: str = "easy", seed: Optional[int] = None) -> Dict[str, Any]:
    rng = random.Random(seed)
    pool = ["Caesar", "Atbash", "Vigenère", "Substitution"]
    weight = _rng_by_difficulty(difficulty)
    if weight < 0.4:
        algos = ["Caesar", "Atbash"]
    elif weight < 0.8:
        algos = ["Caesar", "Atbash", "Vigenère"]
    else:
        algos = pool
    algo = rng.choice(algos)
    plaintext = rng.choice(COMMON_DICT_WORDS)
    if difficulty == "hard":
        plaintext = f"{rng.choice(COMMON_DICT_WORDS)} {rng.choice(COMMON_DICT_WORDS)}"
    elif difficulty == "medium":
        plaintext = plaintext + str(rng.randint(10, 999))

    if algo == "Caesar":
        shift = rng.randint(1, 25)
        ciphertext = caesar_encrypt(plaintext, shift)
        key_info = {"shift": shift}
        hints = [
            f"The first letter of the plaintext is {plaintext[0]!r}.",
            f"Try shifts 1–13 first (most common are small).",
            f"Known letter freq order in English: {ENGLISH_COMMON[:8]}...",
        ]
    elif algo == "Atbash":
        ciphertext = atbash_encrypt(plaintext)
        key_info = {"rule": "A↔Z, B↔Y, …"}
        hints = [
            "Atbash is its own inverse — apply the same rule to the ciphertext.",
            f"First decoded letter is {atbash_decrypt(ciphertext[0])!r}.",
        ]
    elif algo == "Vigenère":
        keyword = rng.choice(["SECRET", "CRYPTO", "KEY", "CIPHER", "PYTHON", "VIGENERE"])
        ciphertext = vigenere_encrypt(plaintext, keyword)
        key_info = {"keyword": keyword}
        hints = [
            f"Keyword length: {len(keyword)}",
            f"Keyword starts with: {keyword[0]!r}",
            f"Original plaintext word length: {len(plaintext)}",
        ]
    else:  # Substitution
        key = monoalphabetic_key(seed or 42)
        ciphertext = monoalphabetic_encrypt(plaintext, key)
        key_info = {"key": key}
        hints = [
            f"Plaintext word length: {len(plaintext)}",
            f"Most frequent ciphertext letter corresponds to plaintext: "
            f"{max(set(ciphertext), key=ciphertext.count)!r}",
        ]

    return {
        "algo": algo,
        "ciphertext": ciphertext,
        "plaintext_answer": plaintext,
        "key_info": key_info,
        "hints": hints,
        "difficulty": difficulty,
        "xp": {"easy": 30, "medium": 60, "hard": 120}[difficulty] if difficulty in ("easy", "medium", "hard") else 30,
    }


def generate_guess_the_cipher_level(difficulty: str = "easy", seed: Optional[int] = None) -> Dict[str, Any]:
    lvl = generate_crack_the_cipher_level(difficulty=difficulty, seed=seed)
    algo = lvl["algo"]
    options = ["Caesar", "Atbash", "Vigenère", "Substitution"]
    if algo not in options:
        options[0] = algo
    rng = random.Random((seed or 0) + 7)
    rng.shuffle(options)
    return {
        "ciphertext": lvl["ciphertext"],
        "options": options,
        "correct_algo": algo,
        "explanation": (
            f"{algo} was used to encrypt a plaintext of length {len(lvl['plaintext_answer'])}."
        ),
        "difficulty": difficulty,
        "xp": {"easy": 20, "medium": 40, "hard": 80}[difficulty] if difficulty in ("easy", "medium", "hard") else 20,
    }


def generate_brute_force_challenge(difficulty: str = "easy", seed: Optional[int] = None) -> Dict[str, Any]:
    rng = random.Random(seed)
    weight = _rng_by_difficulty(difficulty)
    if weight < 0.4:
        pwd = rng.choice(["1234", "0000", "abcd", "qwer", "1111", "7777"])
        char_space = "digits OR lowercase letters"
        max_guesses = 12
    elif weight < 0.8:
        pwd = rng.choice(["pass1", "ank12", "qw3rty", "abc99", "hell0", "j0hnc"])
        char_space = "lowercase letters + digits"
        max_guesses = 20
    else:
        pwd = rng.choice(["zebra7", "jupiter1", "xray99", "pilot03", "falcon2", "monkey5"])
        char_space = "lowercase letters + a single digit at end"
        max_guesses = 30
    return {
        "target_password_length": len(pwd),
        "character_space": char_space,
        "max_attempts": max_guesses,
        "answer": pwd,
        "hints": [
            f"Length: {len(pwd)}",
            f"First character: {pwd[0]!r}",
            f"Last character: {pwd[-1]!r}",
        ],
        "difficulty": difficulty,
        "xp": {"easy": 25, "medium": 55, "hard": 110}[difficulty] if difficulty in ("easy", "medium", "hard") else 25,
    }


def generate_cipher_puzzle(difficulty: str = "easy", seed: Optional[int] = None) -> Dict[str, Any]:
    lvl = generate_crack_the_cipher_level(difficulty=difficulty, seed=seed)
    clues = [
        f"The original sentence/plaintext starts with {lvl['plaintext_answer'][0]!r}.",
        f"It uses the {lvl['algo']} scheme.",
        f"Plaintext length: {len(lvl['plaintext_answer'])}.",
    ]
    return {
        "clues": clues,
        "ciphertext": lvl["ciphertext"],
        "plaintext_answer": lvl["plaintext_answer"],
        "algo": lvl["algo"],
        "key_info": lvl["key_info"],
        "hints": lvl["hints"],
        "difficulty": difficulty,
        "xp": {"easy": 35, "medium": 70, "hard": 140}[difficulty] if difficulty in ("easy", "medium", "hard") else 35,
    }


def generate_key_guessing_level(difficulty: str = "easy", seed: Optional[int] = None) -> Dict[str, Any]:
    rng = random.Random(seed)
    entry = rng.choice(WEAK_RSA_KEYS_DEMO)
    weight = _rng_by_difficulty(difficulty)
    ciphertext_demo = pow(entry["plaintext_demo"], entry["public"]["e"], entry["public"]["n"])
    answer_factor = entry["private_p"]
    return {
        "key_label": entry["key_label"],
        "public_key": entry["public"],
        "ciphertext_integer": ciphertext_demo,
        "correct_prime_factor": answer_factor,
        "correct_plaintext": entry["plaintext_demo"],
        "max_attempts": max(3, int(8 - weight * 4)),
        "hints": [entry["hint"], f"sqrt(n) ≈ {int(entry['public']['n'] ** 0.5)}"],
        "difficulty": difficulty,
        "xp": {"easy": 40, "medium": 80, "hard": 160}[difficulty] if difficulty in ("easy", "medium", "hard") else 40,
    }


def generate_hash_detective_level(difficulty: str = "easy", seed: Optional[int] = None) -> Dict[str, Any]:
    rng = random.Random(seed)
    catalog = precompute_hash_catalog()
    weight = _rng_by_difficulty(difficulty)
    algos = ["md5", "sha1", "sha256"] if weight > 0.7 else ["md5", "sha256"]
    algo = rng.choice(algos)
    # Pick a random preimage from the catalog and build its hash for chosen algo
    plain, note = rng.choice(HASH_PREIMAGES)
    digest = hashlib.new(algo, plain.encode("utf-8")).hexdigest()
    return {
        "hash": digest,
        "algorithm_options": ["md5", "sha1", "sha256", "sha512"],
        "correct_algorithm": algo,
        "preimage_answer": plain,
        "note": note,
        "difficulty": difficulty,
        "xp": {"easy": 30, "medium": 60, "hard": 120}[difficulty] if difficulty in ("easy", "medium", "hard") else 30,
    }


def generate_encryption_race_level(seed: Optional[int] = None) -> Dict[str, Any]:
    """Generate a prediction question + deterministic speed labels.

    Since educational — we use known *orders of magnitude* (not real runtime on host)
    so the game is deterministic and cross-platform.
    """
    rng = random.Random(seed)
    payload_bytes = rng.choice([16, 64, 256, 1024, 8192])
    pair = rng.choice([
        ("AES-256-GCM", "RSA-2048", "AES-256-GCM"),   # symmetric is always ~100x faster
        ("DES-ECB", "AES-256-GCM", "AES-256-GCM"),    # AES still wins handily
        ("SHA-256", "bcrypt(cost=12)", "SHA-256"),     # SHA is fast; bcrypt is intentionally slow
        ("MD5", "SHA-512", "MD5"),                     # MD5 slightly faster
        ("ChaCha20", "3DES", "ChaCha20"),              # ChaCha is faster on most CPUs
    ])
    return {
        "payload_bytes": payload_bytes,
        "candidate_a": pair[0],
        "candidate_b": pair[1],
        "faster_algorithm": pair[2],
        "ratio_estimate": 90 if pair[2] == "AES-256-GCM" and "RSA" in (pair[0], pair[1]) else 5,
        "xp": 50,
    }


def pick_vulnerability(seed: Optional[int] = None) -> Dict[str, Any]:
    rng = random.Random(seed)
    item = rng.choice(VULNERABILITY_SNIPPETS)
    return {
        "id": item["id"],
        "title": item["title"],
        "language": item["language"],
        "code": item["code"],
        "options": list(item["options"]),
        "correct_index": item["correct_index"],
        "severity": item["severity"],
        "explanation": item["explanation"],
        "cwe": item["cwe"],
        "xp": 70,
    }


# ---------------------------------------------------------------------------
# Daily cipher — deterministic per date
# ---------------------------------------------------------------------------
def _day_seed() -> int:
    today = _dt.date.today()
    return today.year * 10000 + today.month * 100 + today.day


def generate_daily_cipher() -> Dict[str, Any]:
    seed = _day_seed()
    difficulty = "medium" if (seed % 3) == 0 else ("hard" if (seed % 5) == 0 else "easy")
    level = generate_crack_the_cipher_level(difficulty=difficulty, seed=seed)
    date_str = _dt.date.today().isoformat()
    return {
        "date": date_str,
        "daily_number": (seed % 9000) + 1,
        "algo": level["algo"],
        "ciphertext": level["ciphertext"],
        "plaintext_answer": level["plaintext_answer"],
        "hints": level["hints"],
        "difficulty": difficulty,
        "xp": level["xp"] + 15,  # bonus for daily
    }


CRAZY_MODE_QUESTIONS = (
    {"q": "Which block cipher mode produces identical ciphertext for identical plaintext blocks?", "a": "ECB",
     "choices": ["ECB", "CBC", "CFB", "GCM"],
     "category": "crypto"},
    {"q": "SHA-256 produces digests of how many bits?", "a": "256",
     "choices": ["128", "160", "256", "512"], "category": "hash"},
    {"q": "How many rounds does DES use?", "a": "16",
     "choices": ["8", "16", "32", "64"], "category": "history"},
    {"q": "Which cipher invented by Rivest–Shamir–Adleman uses factoring?", "a": "RSA",
     "choices": ["RSA", "AES", "DES", "ECC"], "category": "asymmetric"},
    {"q": "Number of letters in English alphabet (Caesar cipher shift space)", "a": "26",
     "choices": ["24", "25", "26", "27"], "category": "cipher"},
    {"q": "AES uses a substitution box commonly called a(n) ____ box.", "a": "S",
     "choices": ["P", "S", "K", "H"], "category": "crypto"},
    {"q": "Weak hashing algorithm deprecated after collisions in 2004.", "a": "MD5",
     "choices": ["SHA-1", "MD5", "SHA-256", "BLAKE2"], "category": "history"},
    {"q": "Enigma machine, how many rotors in typical Army version?", "a": "3",
     "choices": ["2", "3", "4", "5"], "category": "history"},
    {"q": "What does TOR stand for?", "a": "THE ONION ROUTER",
     "choices": ["TERMINAL OR ROUTER", "THE ONION ROUTER", "TRACE ON ROUTE", "TOP OPEN ROUTE"],
     "category": "networking"},
    {"q": "Public-key cryptography standard number 1 (PKCS#1) defines:", "a": "RSA",
     "choices": ["AES", "RSA", "ECC", "HMAC"], "category": "standards"},
    {"q": "Default port for HTTPS", "a": "443",
     "choices": ["80", "22", "443", "8080"], "category": "networking"},
    {"q": "Which hash uses 20-byte output and was designed by the NSA?", "a": "SHA-1",
     "choices": ["MD5", "SHA-1", "SHA-256", "HAVAL"], "category": "hash"},
    {"q": "Non-deterministic random number generator acronym.", "a": "NDRNG",
     "choices": ["PRNG", "NDRNG", "CTR_DRBG", "HSM"], "category": "crypto"},
    {"q": "Length of an AES-256 key in bytes", "a": "32",
     "choices": ["16", "24", "32", "64"], "category": "crypto"},
    {"q": "Which TCP port is SSH?", "a": "22",
     "choices": ["21", "22", "23", "25"], "category": "networking"},
    {"q": "Kerckhoffs's principle states the only secret should be the ____.", "a": "KEY",
     "choices": ["IV", "KEY", "ALGORITHM", "NONCE"], "category": "crypto"},
    {"q": "XOR-ing ciphertext with known plaintext yields the ____.", "a": "KEYSTREAM",
     "choices": ["KEYSTREAM", "HASH", "IV", "MAC"], "category": "crypto"},
    {"q": "A rainbow table stores precomputed ____.", "a": "HASHES",
     "choices": ["KEYS", "HASHES", "NONCES", "IVS"], "category": "security"},
    {"q": "Diffie–Hellman enables two parties to agree on a shared ____ over insecure channel.", "a": "SECRET",
     "choices": ["SECRET", "IV", "CERTIFICATE", "HASH"], "category": "crypto"},
    {"q": "HMAC combines a secret key with a ____ function.", "a": "HASH",
     "choices": ["HASH", "STREAM", "BLOCK", "MAC"], "category": "crypto"},
    {"q": "Which mode performs authenticated encryption + integrity in AES?", "a": "GCM",
     "choices": ["ECB", "CBC", "GCM", "CTR"], "category": "crypto"},
    {"q": "Frequency analysis attacks classic monoalphabetic ciphers like:", "a": "CAESAR",
     "choices": ["AES", "CAESAR", "RSA", "OTP"], "category": "attacks"},
    {"q": "Padding oracle attacks exploit the ____ padding validation.", "a": "PKCS7",
     "choices": ["PKCS7", "ISO9797", "ZERO", "NONE"], "category": "attacks"},
    {"q": "TLS handshake uses which protocol for key agreement commonly?", "a": "ECDHE",
     "choices": ["DES", "ECDHE", "MD5", "ECB"], "category": "networking"},
    {"q": "OTP can only be cracked if:", "a": "REUSED",
     "choices": ["REUSED", "LONG", "BINARY", "RANDOM"], "category": "crypto"},
)


def generate_crazy_mode_level(seed: Optional[int] = None, question_index: int = 0, total_questions: int = 5) -> Dict[str, Any]:
    rng = random.Random(seed if seed is not None else time.time_ns() % (2**31))
    qpool = list(CRAZY_MODE_QUESTIONS)
    rng.shuffle(qpool)
    q = qpool[question_index % len(qpool)]
    choices = list(q["choices"])
    rng.shuffle(choices)
    return {
        "level_id": f"crazy_{question_index + 1}",
        "game_id": "crazy_mode",
        "difficulty": "INSANE",
        "max_questions": total_questions,
        "question_number": question_index + 1,
        "time_limit_seconds": 300,
        "lives": 2,
        "category": q["category"],
        "question": q["q"],
        "choices": choices,
        "correct_answer": q["a"],
        "hints": [],
        "xp": 400,
        "lives_total": 2,
        "show_only_choice_mode": True,
    }


def generate_crazy_mode_question_bank(total_questions: int = 5, seed: Optional[int] = None) -> List[Dict[str, Any]]:
    rng = random.Random(seed if seed is not None else time.time_ns() % (2**31))
    qpool = list(CRAZY_MODE_QUESTIONS)
    rng.shuffle(qpool)
    bank = []
    for i in range(min(total_questions, len(qpool))):
        q = qpool[i]
        choices = list(q["choices"])
        rng.shuffle(choices)
        bank.append({
            "level_id": f"crazy_{i + 1}",
            "question_number": i + 1,
            "category": q["category"],
            "question": q["q"],
            "choices": choices,
            "correct_answer": q["a"],
            "xp": 400,
        })
    return bank



# ---------------------------------------------------------------------------
# Game catalog — used by the /api/games/types endpoint
# ---------------------------------------------------------------------------
GAME_CATALOG: Tuple[Dict[str, Any], ...] = (
    {
        "id": "crack_cipher",
        "name": "Crack the Cipher",
        "icon": "fa-key",
        "color": "success",
        "short_description": "Decrypt ciphertexts produced by Caesar, Atbash, Vigenère, and more.",
        "long_description": (
            "Given a ciphertext (and sometimes a hint), type the original plaintext. "
            "Supports Caesar shift, Atbash mirror, Vigenère keyword, and monoalphabetic substitution."
        ),
        "difficulties": ["Easy", "Medium", "Hard"],
        "xp_range": "30 – 140 XP",
        "lives": True,
        "timer": True,
        "hints": True,
    },
    {
        "id": "guess_cipher",
        "name": "Guess the Cipher",
        "icon": "fa-circle-question",
        "color": "info",
        "short_description": "Show ciphertext — pick which cipher produced it.",
        "long_description": (
            "Four cipher options are shown. Pick the one that produced the given ciphertext."
        ),
        "difficulties": ["Easy", "Medium", "Hard"],
        "xp_range": "20 – 80 XP",
        "lives": True,
        "timer": True,
        "hints": False,
    },
    {
        "id": "brute_force",
        "name": "Brute Force Challenge",
        "icon": "fa-bomb",
        "color": "danger",
        "short_description": "Demo weak passwords — guess the target within limited attempts.",
        "long_description": (
            "Purely educational: a very short weak demo password is chosen with generous hints. "
            "Watch how fast guesses cut the search space down."
        ),
        "difficulties": ["Easy", "Medium", "Hard"],
        "xp_range": "25 – 110 XP",
        "lives": True,
        "timer": True,
        "hints": True,
    },
    {
        "id": "cipher_puzzle",
        "name": "Cipher Puzzle",
        "icon": "fa-puzzle-piece",
        "color": "warning",
        "short_description": "Solve a cipher with clues — like a cryptographic mini-mystery.",
        "long_description": (
            "You receive encrypted text plus narrative clues. Identify the scheme, then decrypt."
        ),
        "difficulties": ["Easy", "Medium", "Hard"],
        "xp_range": "35 – 140 XP",
        "lives": True,
        "timer": True,
        "hints": True,
    },
    {
        "id": "key_guessing",
        "name": "Key Guessing",
        "icon": "fa-key-skeleton",
        "color": "primary",
        "short_description": "Factor demo tiny RSA moduli — why weak keys break everything.",
        "long_description": (
            "Uses toy 4–8-bit RSA moduli to teach the principle: once n factors, the private key is known."
        ),
        "difficulties": ["Easy", "Medium", "Hard"],
        "xp_range": "40 – 160 XP",
        "lives": True,
        "timer": True,
        "hints": True,
    },
    {
        "id": "hash_detective",
        "name": "Hash Detective",
        "icon": "fa-magnifying-glass",
        "color": "secondary",
        "short_description": "Identify MD5 / SHA-1 / SHA-256 hashes and crack a few known preimages.",
        "long_description": (
            "Two-parter: pick the correct hash algorithm, then identify the weak password preimage from a tiny rainbow table."
        ),
        "difficulties": ["Easy", "Medium", "Hard"],
        "xp_range": "30 – 120 XP",
        "lives": True,
        "timer": True,
        "hints": True,
    },
    {
        "id": "encryption_race",
        "name": "Encryption Race",
        "icon": "fa-gauge-high",
        "color": "success",
        "short_description": "Predict which algorithm is faster — then see the benchmark result.",
        "long_description": (
            "Pick A or B. Win XP for correctly guessing the faster algorithm for a chosen payload size."
        ),
        "difficulties": ["Single"],
        "xp_range": "50 XP",
        "lives": False,
        "timer": False,
        "hints": False,
    },
    {
        "id": "find_vulnerability",
        "name": "Find the Vulnerability",
        "icon": "fa-shield-halved",
        "color": "danger",
        "short_description": "Spot the crypto flaw in realistic Python snippets.",
        "long_description": (
            "Hardcoded keys, MD5 passwords, weak PRNGs, ECB mode, tiny RSA keys — one option is correct."
        ),
        "difficulties": ["Single"],
        "xp_range": "70 XP",
        "lives": True,
        "timer": True,
        "hints": False,
    },
    {
        "id": "daily_cipher",
        "name": "Daily Cipher",
        "icon": "fa-calendar-day",
        "color": "warning",
        "short_description": "A brand new cipher challenge every day. Build your streak!",
        "long_description": (
            "Deterministic puzzle based on the calendar date — come back tomorrow for a new one."
        ),
        "difficulties": ["Daily"],
        "xp_range": "45 – 155 XP",
        "lives": True,
        "timer": False,
        "hints": True,
    },
    {
        "id": "crazy_mode",
        "name": "🔥 CRAZY MODE 🔥",
        "icon": "fa-skull-crossbones",
        "color": "danger",
        "short_description": "Mixed-field chaos! 2 chances. 5 minutes. Fail → SITE GOES CRAZY. Win → CONFETTI VICTORY!",
        "long_description": (
            "Random questions from crypto, networking, security, cipher trivia. Only 2 WRONG CHANCES "
            "and 5 MINUTES on the clock. Every wrong answer inches you closer to a HORRIFIC RED CRASH "
            "SIMULATION with LOUD horrific sounds. Guess all right → trumpet congratulations + light "
            "show + site GOES CRAZY with celebration flashes! NOT FOR THE FAINT OF HEART."
        ),
        "difficulties": ["INSANE"],
        "xp_range": "500 – 2000 XP",
        "lives": True,
        "timer": True,
        "hints": False,
    },
)


RANKS: Tuple[Dict[str, Any], ...] = (
    {"name": "Novice",         "min_xp": 0,     "title": "Code Apprentice", "icon": "fa-seedling"},
    {"name": "Decoder",        "min_xp": 250,   "title": "Junior Codebreaker", "icon": "fa-compass"},
    {"name": "Cryptographer",  "min_xp": 1000,  "title": "Senior Cryptographer", "icon": "fa-cipher"},
    {"name": "Cipher Hunter",  "min_xp": 3500,  "title": "Threat Intel Lead", "icon": "fa-crosshairs"},
    {"name": "Crypto Master",  "min_xp": 9000,  "title": "Crypto Master", "icon": "fa-crown"},
)


def rank_for_xp(xp: int) -> Dict[str, Any]:
    rank = RANKS[0]
    for r in RANKS:
        if xp >= r["min_xp"]:
            rank = r
    return rank