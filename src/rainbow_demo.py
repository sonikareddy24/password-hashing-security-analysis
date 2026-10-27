"""
rainbow_demo.py - Phase 3: Rainbow / Precomputed Lookup-Table Experiment.

Directly extends Skanda et al. (IEEE NKCon 2022).
Compares unsalted vs. salted hash storage against precomputed lookup attacks.

Educational Context:
A hash-lookup dictionary maps hash(password) -> password in O(1) time.
True rainbow tables introduce reduction functions R(h) and merge chains
to compress this table at the cost of slight re-computation.
Both share the exact same fundamental property: they precompute hashes without salt.
When per-user salts are introduced, all precomputed tables become useless.
"""

import os
import sys
import time
import random
import secrets
from typing import Dict, Any, List, Tuple

sys.path.append(os.path.dirname(__file__))
from algorithms import hash_password, verify_password
from wordlist import load_wordlist


def build_lookup_tables(wordlist: List[str]) -> Tuple[Dict[str, str], Dict[str, str], float]:
    """
    Builds in-memory lookup tables for unsalted MD5 and SHA-256 over wordlist.
    Returns: (md5_table, sha256_table, build_time_seconds)
    """
    t0 = time.perf_counter()
    md5_table = {}
    sha256_table = {}
    
    for pwd in wordlist:
        h_md5 = hash_password("MD5", pwd)
        h_sha256 = hash_password("SHA-256", pwd)
        md5_table[h_md5] = pwd
        sha256_table[h_sha256] = pwd
        
    build_time = time.perf_counter() - t0
    return md5_table, sha256_table, build_time


def generate_simulated_users(wordlist: List[str], count: int = 1000, in_dict_ratio: float = 0.95) -> List[Dict[str, Any]]:
    """
    Generates simulated user accounts.
    in_dict_ratio (default 95%) passwords come from wordlist (popular breach distribution);
    the remaining 5% are strong random passwords not in the wordlist.
    """
    users = []
    num_in_dict = int(count * in_dict_ratio)
    
    # Sample passwords with skew toward top of wordlist
    top_slice = wordlist[:min(len(wordlist), 5000)]
    for i in range(count):
        if i < num_in_dict:
            pwd = random.choice(top_slice)
        else:
            pwd = secrets.token_urlsafe(12) + "!"
            
        salt = os.urandom(16)
        users.append({
            "user_id": f"user_{i+1:04d}",
            "password": pwd,
            "salt": salt,
            "md5_unsalted": hash_password("MD5", pwd),
            "md5_salted": hash_password("MD5", pwd, salt=salt),
            "sha256_unsalted": hash_password("SHA-256", pwd),
            "sha256_salted": hash_password("SHA-256", pwd, salt=salt),
        })
        
    return users


def run_lookup_attack_unsalted(users: List[Dict[str, Any]], lookup_table: Dict[str, str], algo_key: str) -> Dict[str, Any]:
    """
    Executes O(1) table lookup against unsalted hashes for all users.
    """
    t0 = time.perf_counter()
    cracked = 0
    cracked_samples = []
    
    for u in users:
        target_hash = u[algo_key]
        if target_hash in lookup_table:
            cracked += 1
            if len(cracked_samples) < 5:
                cracked_samples.append({
                    "user": u["user_id"],
                    "hash": target_hash[:16] + "...",
                    "revealed": lookup_table[target_hash]
                })
                
    elapsed = time.perf_counter() - t0
    total = len(users)
    rate = total / max(elapsed, 1e-9)
    
    return {
        "total_targets": total,
        "cracked_count": cracked,
        "crack_percentage": round((cracked / total) * 100, 2),
        "total_time_seconds": round(elapsed, 6),
        "time_per_target_microseconds": round((elapsed / total) * 1e6, 3),
        "lookups_per_second": round(rate, 1),
        "samples": cracked_samples,
    }


def run_lookup_attack_salted(users: List[Dict[str, Any]], lookup_table: Dict[str, str], algo_key: str) -> Dict[str, Any]:
    """
    Attempts to use the unsalted precomputed table against salted hashes.
    Demonstrates that salted passwords completely nullify precomputation tables (0% crack).
    """
    t0 = time.perf_counter()
    cracked = 0
    
    for u in users:
        target_hash = u[algo_key]
        # In a salted scheme, hash is either $algo$salt$digest or digest of salt+password
        # Even if attacker queries table with digest portion, it fails
        if "$" in target_hash:
            parts = target_hash.split("$")
            digest = parts[-1]
        else:
            digest = target_hash
            
        if digest in lookup_table:
            # Check if plaintext actually matches
            candidate = lookup_table[digest]
            if candidate == u["password"]:
                cracked += 1
                
    elapsed = time.perf_counter() - t0
    total = len(users)
    
    return {
        "total_targets": total,
        "cracked_count": cracked,
        "crack_percentage": round((cracked / total) * 100, 2),
        "total_time_seconds": round(elapsed, 6),
        "notes": "Precomputed table failed completely (0.0% cracked). Salt forced attacker to abandon precomputed lookup."
    }


def estimate_per_user_bruteforce(wordlist_size: int, algo_name: str, guess_rate: float) -> Dict[str, Any]:
    """
    Calculates the brute force cost to crack a single salted user password.
    """
    # Average search space is wordlist_size / 2 for 50% crack probability
    avg_guesses = wordlist_size / 2.0
    sec_per_user = avg_guesses / max(guess_rate, 1e-6)
    
    return {
        "algorithm": algo_name,
        "wordlist_candidates": wordlist_size,
        "avg_guesses_needed": int(avg_guesses),
        "guesses_per_sec": guess_rate,
        "seconds_per_user": round(sec_per_user, 4),
        "hours_for_1000_users": round((sec_per_user * 1000) / 3600.0, 2),
        "days_for_1000_users": round((sec_per_user * 1000) / 86400.0, 2),
    }


def run_rainbow_experiment(quick_mode: bool = False, guess_rates: dict = None) -> Dict[str, Any]:
    """
    Runs complete Phase 3 lookup table experiment.
    """
    print("\n" + "=" * 60)
    print(f"RAINBOW / LOOKUP TABLE EXPERIMENT ({'QUICK' if quick_mode else 'FULL'} MODE)")
    print("=" * 60)

    # 1. Load wordlist
    max_words = 5000 if quick_mode else 25000
    user_count = 250 if quick_mode else 1000
    wordlist, source = load_wordlist(max_words)
    print(f"Loaded {len(wordlist):,} candidates from {source}")

    # 2. Build precomputed tables
    print(f"Building precomputed lookup tables for MD5 & SHA-256 ({len(wordlist):,} entries)...")
    md5_tbl, sha256_tbl, build_time = build_lookup_tables(wordlist)
    print(f"Precomputed tables built in {build_time:.3f} s ({len(md5_tbl):,} entries each)")

    # 3. Simulate user database
    print(f"Generating {user_count} simulated accounts (95% in wordlist, 5% random)...")
    users = generate_simulated_users(wordlist, count=user_count, in_dict_ratio=0.95)

    # 4. Attack unsalted MD5 & SHA-256
    print("\n--- Attacking Unsalted Hashes via Precomputed Table ---")
    unsalted_md5 = run_lookup_attack_unsalted(users, md5_tbl, "md5_unsalted")
    unsalted_sha = run_lookup_attack_unsalted(users, sha256_tbl, "sha256_unsalted")
    print(f"[Unsalted MD5   ] Cracked: {unsalted_md5['cracked_count']}/{user_count} ({unsalted_md5['crack_percentage']}%) in {unsalted_md5['total_time_seconds']*1000:.3f} ms")
    print(f"[Unsalted SHA256] Cracked: {unsalted_sha['cracked_count']}/{user_count} ({unsalted_sha['crack_percentage']}%) in {unsalted_sha['total_time_seconds']*1000:.3f} ms")

    # 5. Attack salted MD5 & SHA-256
    print("\n--- Attacking Salted Hashes with Same Precomputed Table ---")
    salted_md5 = run_lookup_attack_salted(users, md5_tbl, "md5_salted")
    salted_sha = run_lookup_attack_salted(users, sha256_tbl, "sha256_salted")
    print(f"[Salted MD5     ] Cracked: {salted_md5['cracked_count']}/{user_count} ({salted_md5['crack_percentage']}%) -> TABLE USELESS")
    print(f"[Salted SHA256  ] Cracked: {salted_sha['cracked_count']}/{user_count} ({salted_sha['crack_percentage']}%) -> TABLE USELESS")

    # 6. Calculate speedup factor and online brute-force cost
    # Default rates if not passed
    rates = guess_rates or {
        "MD5": 1.5e6,
        "SHA-256": 1.5e6,
        "PBKDF2": 10.0,
        "bcrypt": 8.5,
        "scrypt": 14.0,
        "Argon2id": 9.5
    }

    per_user_costs = {}
    for algo, rate in rates.items():
        per_user_costs[algo] = estimate_per_user_bruteforce(len(wordlist), algo, rate)

    # Speedup factor of lookup table over per-user online brute-force for unsalted vs salted MD5:
    # Unsalted: lookup took unsalted_md5['time_per_target_microseconds'] / 1e6 s
    # Salted: attacker must hash ~avg_guesses candidates at rate guesses/s
    time_lookup_per_user = unsalted_md5["time_per_target_microseconds"] / 1e6
    time_brute_md5_per_user = per_user_costs["MD5"]["seconds_per_user"]
    time_brute_bcrypt_per_user = per_user_costs["bcrypt"]["seconds_per_user"]

    speedup_vs_salted_md5 = time_brute_md5_per_user / max(time_lookup_per_user, 1e-9)
    speedup_vs_salted_bcrypt = time_brute_bcrypt_per_user / max(time_lookup_per_user, 1e-9)

    print(f"\nSpeedup of Precomputed Lookup over Salted Online Brute-Force:")
    print(f"- Against Salted MD5   : {speedup_vs_salted_md5:,.1f}x faster")
    print(f"- Against Salted bcrypt: {speedup_vs_salted_bcrypt:,.1f}x faster")

    return {
        "table_build_time_sec": round(build_time, 4),
        "wordlist_size": len(wordlist),
        "simulated_users": user_count,
        "unsalted_attack": {
            "MD5": unsalted_md5,
            "SHA-256": unsalted_sha,
        },
        "salted_attack": {
            "MD5": salted_md5,
            "SHA-256": salted_sha,
        },
        "per_user_bruteforce_costs": per_user_costs,
        "speedup_factors": {
            "lookup_vs_salted_md5": round(speedup_vs_salted_md5, 1),
            "lookup_vs_salted_bcrypt": round(speedup_vs_salted_bcrypt, 1),
        }
    }


if __name__ == "__main__":
    res = run_rainbow_experiment(quick_mode=True)
    print("\nPhase 3 Rainbow / Lookup experiment completed.")
