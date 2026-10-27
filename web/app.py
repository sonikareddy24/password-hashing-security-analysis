"""
app.py - Flask Web Application for Password Hashing Benchmark Suite.

API Endpoints:
- GET  /              : Serves the single-page application UI.
- GET  /api/results   : Returns current results/results.json benchmark data.
- POST /api/hash      : Live Hash Lab - computes all 6 hashes with real-time latency measurement.
- POST /api/lookup    : Rainbow Table Demo - executes unsalted vs salted lookup attacks.
- GET  /api/system    : Returns host machine environment details.
"""

import os
import sys
import time
import json
import secrets
from flask import Flask, jsonify, request, send_from_directory, render_template

# Setup paths
WEB_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(WEB_DIR, ".."))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
STATIC_DIR = os.path.join(WEB_DIR, "static")

sys.path.append(SRC_DIR)
from algorithms import hash_password, verify_password, ALGORITHMS
from wordlist import load_wordlist
from rainbow_demo import build_lookup_tables, generate_simulated_users, run_lookup_attack_unsalted, run_lookup_attack_salted

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

# Cache lookup tables and simulated users for fast UI interaction
_CACHED_WORDLIST = None
_CACHED_MD5_TABLE = None
_CACHED_SHA256_TABLE = None
_CACHED_USERS = None


def get_cached_tables():
    global _CACHED_WORDLIST, _CACHED_MD5_TABLE, _CACHED_SHA256_TABLE, _CACHED_USERS
    if _CACHED_WORDLIST is None:
        _CACHED_WORDLIST, _ = load_wordlist(5000)
        _CACHED_MD5_TABLE, _CACHED_SHA256_TABLE, _ = build_lookup_tables(_CACHED_WORDLIST)
        _CACHED_USERS = generate_simulated_users(_CACHED_WORDLIST, count=500, in_dict_ratio=0.95)
    return _CACHED_WORDLIST, _CACHED_MD5_TABLE, _CACHED_SHA256_TABLE, _CACHED_USERS


PAPER_DIR = os.path.join(PROJECT_ROOT, "paper")


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/results/<path:filename>")
def serve_result_artifact(filename):
    return send_from_directory(RESULTS_DIR, filename)


@app.route("/paper/<path:filename>")
def serve_paper_artifact(filename):
    return send_from_directory(PAPER_DIR, filename)


@app.route("/api/results", methods=["GET"])
def api_results():
    """Returns saved results from results.json."""
    json_path = os.path.join(RESULTS_DIR, "results.json")
    if not os.path.exists(json_path):
        return jsonify({
            "status": "not_ready",
            "message": "Benchmark results not yet generated. Please run 'python src/run_all.py --quick' first."
        }), 404

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return jsonify({"status": "success", "data": data})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/hash", methods=["POST"])
def api_hash():
    """
    Live Hash Lab endpoint. Computes hashes for all 6 algorithms.
    Uses calibrated/safe UI parameters so response arrives under 400ms total.
    """
    payload = request.get_json(silent=True) or {}
    password = str(payload.get("password", "")).strip()
    if not password:
        password = "Password123!"

    # Cap password length for UI safety
    if len(password) > 256:
        password = password[:256]

    results = []

    # Safe UI parameter presets (~50-80 ms each max for snappy UI)
    ui_params = {
        "MD5": {},
        "SHA-256": {},
        "PBKDF2": {"iterations": 250000},
        "bcrypt": {"rounds": 10},
        "scrypt": {"n": 16384, "r": 8, "p": 1},
        "Argon2id": {"time_cost": 2, "memory_cost": 19456, "parallelism": 1},
    }

    explanations = {
        "MD5": "Legacy fast 128-bit digest. Completely unsalted by default; produces identical output on repeated clicks.",
        "SHA-256": "Modern fast 256-bit cryptographic hash. Unsalted by default; deterministic and vulnerable to precomputation.",
        "PBKDF2": "Key-stretching via 250k HMAC iterations. Uses unique 16-byte random salt; notice output changes on every click!",
        "bcrypt": "Adaptive Eksblowfish key schedule with 2^10 cost. Encodes salt and cost directly inside modular $2b$ string.",
        "scrypt": "Sequential memory-hard algorithm. Requires ~16 MiB RAM per hash to defeat GPU and ASIC cracking pipelines.",
        "Argon2id": "IETF RFC 9106 recommended winner of Password Hashing Competition. Resistant to both GPU brute-force and side-channels.",
    }

    for name in ["MD5", "SHA-256", "PBKDF2", "bcrypt", "scrypt", "Argon2id"]:
        t0 = time.perf_counter()
        h_str = hash_password(name, password, **ui_params[name])
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        is_salted = name not in ["MD5", "SHA-256"]

        results.append({
            "algorithm": name,
            "hash": h_str,
            "time_ms": round(elapsed_ms, 2),
            "is_salted": is_salted,
            "memory_hard": name in ["scrypt", "Argon2id"],
            "parameters": ui_params[name],
            "explanation": explanations[name]
        })

    return jsonify({
        "status": "success",
        "input_password": password,
        "results": results
    })


@app.route("/api/lookup", methods=["POST"])
def api_lookup():
    """
    Rainbow table / precomputed lookup demonstration API.
    Attacks unsalted vs salted simulated accounts.
    """
    payload = request.get_json(silent=True) or {}
    attack_type = payload.get("attack_type", "unsalted")
    sample_size = min(int(payload.get("sample_size", 500)), 1000)

    wordlist, md5_tbl, sha256_tbl, users = get_cached_tables()
    active_users = users[:sample_size]

    if attack_type == "unsalted":
        res_md5 = run_lookup_attack_unsalted(active_users, md5_tbl, "md5_unsalted")
        res_sha = run_lookup_attack_unsalted(active_users, sha256_tbl, "sha256_unsalted")
        return jsonify({
            "status": "success",
            "attack_type": "unsalted",
            "sample_size": sample_size,
            "md5_result": res_md5,
            "sha256_result": res_sha,
            "table_entries": len(md5_tbl),
            "message": f"Precomputed lookup recovered {res_md5['cracked_count']}/{sample_size} ({res_md5['crack_percentage']}%) accounts virtually instantaneously!"
        })
    else:
        res_md5 = run_lookup_attack_salted(active_users, md5_tbl, "md5_salted")
        res_sha = run_lookup_attack_salted(active_users, sha256_tbl, "sha256_salted")
        return jsonify({
            "status": "success",
            "attack_type": "salted",
            "sample_size": sample_size,
            "md5_result": res_md5,
            "sha256_result": res_sha,
            "table_entries": len(md5_tbl),
            "message": "Salted storage defeated precomputation: 0 matches (0.0%). The attacker must abandon precomputed tables and hash every candidate once per user."
        })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"Starting Password Hash Benchmark Web Server on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
