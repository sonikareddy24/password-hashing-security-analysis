"""
wordlist.py - Manages password wordlist loading and synthetic wordlist generation.
Educational & benchmark only.
"""

import os
from typing import List, Tuple

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
ROCKYOU_PATH = os.path.join(DATA_DIR, "rockyou.txt")
SYNTHETIC_PATH = os.path.join(DATA_DIR, "synthetic_wordlist.txt")


SEED_PASSWORDS = [
    # Top passwords from public breach compilations
    "123456", "password", "123456789", "12345", "12345678", "qwerty", "1234567",
    "dragon", "pussy", "baseball", "football", "master", "monkey", "696969",
    "shadow", "mustang", "sunshine", "superman", "princess", "trustno1",
    "111111", "welcome", "killer", "letmein", "charlie", "cookie", "starwars",
    "freedom", "orange", "jessica", "pepper", "harley", "hannah", "batman",
    "alexander", "monster", "thomas", "computer", "michelle", "ginger",
    "superstar", "chelsea", "arsenal", "liverpool", "barcelona", "realmadrid",
    "playboy", "security", "pass123", "password1", "password123", "admin",
    "admin123", "root", "toor", "default", "guest", "qwerty123", "iloveyou",
    "secret", "money", "matrix", "london", "newyork", "boston", "hunter2",
    "loveme", "fuckyou", "whatever", "coffee", "robert", "daniel", "william",
    "jordan", "summer", "winter", "autumn", "spring", "dragon1", "monkey1",
    "pokemon", "matrix1", "flower", "peanut", "system", "passcode", "hello",
    "test123", "testing", "login", "access", "falcon", "sparky", "magpie",
    "winner", "champion", "diamond", "gold123", "silver", "platinum", "phoenix",
    "emerald", "destiny", "eclipse", "infinity", "genesis", "titan", "phantom",
    "tiger", "lion", "panther", "cheetah", "jaguar", "cougar", "wolf", "eagle",
    "cobra", "viper", "bear", "shark", "dolphin", "falcon", "hawk", "raven",
    "scorpio", "taurus", "gemini", "cancer", "leo", "virgo", "libra", "sagittarius",
    "capricorn", "aquarius", "pisces", "ares", "zeus", "apollo", "hermes", "poseidon",
    "hades", "thor", "odin", "loki", "freya", "anubis", "osiris", "ra", "horus"
]

COMMON_WORDS = [
    "network", "server", "router", "switch", "gateway", "firewall", "client",
    "database", "oracle", "mysql", "postgres", "sqlite", "mongodb", "redis",
    "docker", "kubernetes", "ansible", "jenkins", "gitlab", "github", "bitbucket",
    "terminal", "console", "desktop", "laptop", "mobile", "iphone", "android",
    "windows", "linux", "ubuntu", "debian", "redhat", "centos", "fedora", "macos",
    "coffee", "tea", "beer", "whiskey", "vodka", "wine", "pizza", "burger",
    "music", "guitar", "piano", "drums", "jazz", "rock", "blues", "techno",
    "summer", "winter", "autumn", "spring", "monday", "friday", "sunday",
    "january", "december", "holiday", "vacation", "journey", "galaxy", "universe",
    "stellar", "nebula", "meteor", "comet", "planet", "saturn", "jupiter", "mars"
]

LEET_MAP = {
    'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'
}

SUFFIXES = [
    "", "1", "12", "123", "1234", "0", "01", "7", "8", "9", "99",
    "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    "!", "!!", "@", "#", "$", "!@#", "123!"
]


def apply_leet(word: str) -> str:
    res = []
    for ch in word.lower():
        res.append(LEET_MAP.get(ch, ch))
    return "".join(res)


def generate_synthetic_wordlist(output_path: str = SYNTHETIC_PATH, target_count: int = 30000) -> str:
    """
    Generates a deterministic, realistic synthetic wordlist sorted by approximate frequency.
    Combines high-ranking seed passwords, dictionary roots, and common password mutation rules
    (capitalization, digit append, leet substitutions, punctuation).
    """
    seen = set()
    passwords = []

    def add(pwd: str):
        if pwd and pwd not in seen:
            seen.add(pwd)
            passwords.append(pwd)

    # 1. High-frequency base passwords first
    for p in SEED_PASSWORDS:
        add(p)

    # 2. Append simple digits to base passwords
    for p in SEED_PASSWORDS:
        for s in ["1", "123", "!", "2024", "2025", "12"]:
            add(p + s)

    # 3. Capitalization variants
    for p in SEED_PASSWORDS:
        add(p.capitalize())
        for s in ["1", "123", "!"]:
            add(p.capitalize() + s)

    # 4. Common words + mutations
    for w in COMMON_WORDS:
        add(w)
        add(w.capitalize())
        for s in SUFFIXES:
            add(w + s)
            add(w.capitalize() + s)

    # 5. Leet substitutions
    for p in SEED_PASSWORDS[:50]:
        leet = apply_leet(p)
        add(leet)
        for s in ["", "1", "123", "!"]:
            add(leet + s)

    # 6. Combinations of seed words and years (1970 - 2026)
    for p in SEED_PASSWORDS[:30]:
        for year in range(1980, 2027):
            add(f"{p}{year}")
            add(f"{p.capitalize()}{year}")

    # 7. 4-6 digit numeric pins
    for pin in range(1000, 10000, 1):
        if len(passwords) >= target_count:
            break
        add(str(pin))

    # Pad if needed up to target_count
    idx = 1
    while len(passwords) < target_count:
        add(f"pass_{idx:05d}")
        idx += 1

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for pwd in passwords:
            f.write(pwd + "\n")

    return output_path


def load_wordlist(max_lines: int = 100000) -> Tuple[List[str], str]:
    """
    Returns (wordlist, source_description).
    Checks for data/rockyou.txt; if absent, generates and uses data/synthetic_wordlist.txt.
    """
    if os.path.exists(ROCKYOU_PATH):
        source = f"rockyou.txt (top {max_lines} entries)"
        wordlist = []
        with open(ROCKYOU_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                w = line.strip("\r\n")
                if w:
                    wordlist.append(w)
        return wordlist, source

    # Use or create synthetic wordlist
    if not os.path.exists(SYNTHETIC_PATH):
        generate_synthetic_wordlist(SYNTHETIC_PATH, target_count=30000)

    wordlist = []
    with open(SYNTHETIC_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            w = line.strip("\r\n")
            if w:
                wordlist.append(w)
    source = f"synthetic_wordlist.txt ({len(wordlist)} rule-mutated breach-style passwords)"
    return wordlist, source
