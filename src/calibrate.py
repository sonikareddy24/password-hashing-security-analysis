"""
calibrate.py - Phase 1: Cost Normalization and Machine Calibration.

Tunes slow password hashing algorithms (PBKDF2, bcrypt, scrypt, Argon2id) to a
standard defender cost of approximately 100 ms (~0.100 s) per hash on the host machine.
Profiles fast algorithms (MD5, SHA-256) and documents why they are non-tunable.
Saves calibrated parameters, OWASP baseline parameters, and machine specifications.
"""

import os
import sys
import time
import json
import ssl
import platform
import subprocess
import importlib.metadata
from typing import Dict, Any, Tuple

# Support direct execution
sys.path.append(os.path.dirname(__file__))
from algorithms import hash_password, OWASP_CONFIGS


def get_system_info() -> Dict[str, Any]:
    """Collects host machine hardware and software environment details."""
    cpu_model = platform.processor() or platform.machine()
    if platform.system() == "Darwin":
        try:
            brand = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"]).decode().strip()
            if brand:
                cpu_model = brand
        except Exception:
            pass

    return {
        "os": f"{platform.system()} {platform.release()} ({platform.platform()})",
        "cpu": cpu_model,
        "cpu_arch": platform.machine(),
        "cpu_cores": os.cpu_count(),
        "python_version": platform.python_version(),
        "openssl_version": getattr(ssl, "OPENSSL_VERSION", "Unknown"),
        "bcrypt_version": importlib.metadata.version("bcrypt"),
        "argon2_version": importlib.metadata.version("argon2-cffi"),
    }


def calibrate_md5() -> Dict[str, Any]:
    """Measures single MD5 hash latency (microseconds). Not tunable."""
    n_iters = 50000
    t0 = time.perf_counter()
    for _ in range(n_iters):
        hash_password("MD5", "benchmark_probe_password")
    elapsed = time.perf_counter() - t0
    avg_sec = elapsed / n_iters
    return {
        "tunable": False,
        "parameters": {},
        "target_ms": 100.0,
        "measured_ms": round(avg_sec * 1000, 4),
        "notes": "Non-tunable fixed-digest hash. Executes in microseconds without key-stretching."
    }


def calibrate_sha256() -> Dict[str, Any]:
    """Measures single SHA-256 hash latency (microseconds). Not tunable."""
    n_iters = 50000
    t0 = time.perf_counter()
    for _ in range(n_iters):
        hash_password("SHA-256", "benchmark_probe_password")
    elapsed = time.perf_counter() - t0
    avg_sec = elapsed / n_iters
    return {
        "tunable": False,
        "parameters": {},
        "target_ms": 100.0,
        "measured_ms": round(avg_sec * 1000, 4),
        "notes": "Non-tunable cryptographic digest designed for raw throughput, not password storage."
    }


def calibrate_pbkdf2(target_sec: float = 0.100) -> Dict[str, Any]:
    """Calibrates PBKDF2 iterations to reach target_sec."""
    probe_iters = 100000
    t0 = time.perf_counter()
    hash_password("PBKDF2", "benchmark_probe", iterations=probe_iters)
    probe_time = time.perf_counter() - t0
    
    # Estimate iterations
    rate = probe_iters / max(probe_time, 1e-6)
    est_iters = int(round((target_sec * rate) / 10000.0) * 10000)
    est_iters = max(10000, est_iters)
    
    # Test candidate
    t0 = time.perf_counter()
    hash_password("PBKDF2", "benchmark_probe", iterations=est_iters)
    measured_sec = time.perf_counter() - t0
    
    return {
        "tunable": True,
        "parameters": {"iterations": est_iters, "hash_name": "sha256"},
        "target_ms": round(target_sec * 1000, 2),
        "measured_ms": round(measured_sec * 1000, 2),
        "notes": f"Linear CPU stretching. Calibrated to {est_iters:,} iterations."
    }


def calibrate_bcrypt(target_sec: float = 0.100) -> Dict[str, Any]:
    """Calibrates bcrypt cost (log_rounds) to closest to target_sec."""
    best_cost = 10
    best_diff = float("inf")
    best_time = 0.0

    # Test costs 9, 10, 11, 12
    for cost in [9, 10, 11, 12]:
        t0 = time.perf_counter()
        hash_password("bcrypt", "benchmark_probe", rounds=cost)
        elapsed = time.perf_counter() - t0
        diff = abs(elapsed - target_sec)
        if diff < best_diff:
            best_diff = diff
            best_cost = cost
            best_time = elapsed
        if elapsed > target_sec * 1.5:
            break

    return {
        "tunable": True,
        "parameters": {"rounds": best_cost},
        "target_ms": round(target_sec * 1000, 2),
        "measured_ms": round(best_time * 1000, 2),
        "notes": f"Exponential work factor 2^{best_cost} ({2**best_cost:,} iterations), 4 KiB memory."
    }


def calibrate_scrypt(target_sec: float = 0.100) -> Dict[str, Any]:
    """Calibrates scrypt N (r=8, p=1) to closest to target_sec."""
    candidates = [16384, 32768, 65536, 131072]
    best_n = 32768
    best_diff = float("inf")
    best_time = 0.0

    for n in candidates:
        t0 = time.perf_counter()
        hash_password("scrypt", "benchmark_probe", n=n, r=8, p=1)
        elapsed = time.perf_counter() - t0
        diff = abs(elapsed - target_sec)
        if diff < best_diff:
            best_diff = diff
            best_n = n
            best_time = elapsed
        if elapsed > target_sec * 1.8:
            break

    mem_mib = (128 * 8 * best_n) / (1024 * 1024)
    return {
        "tunable": True,
        "parameters": {"n": best_n, "r": 8, "p": 1, "maxmem": 1024 * 1024 * 1024},
        "target_ms": round(target_sec * 1000, 2),
        "measured_ms": round(best_time * 1000, 2),
        "notes": f"Memory-hard function with N={best_n} (approx {mem_mib:.1f} MiB RAM)."
    }


def calibrate_argon2id(target_sec: float = 0.100) -> Dict[str, Any]:
    """Calibrates Argon2id memory and time cost (parallelism 1) to ~target_sec."""
    # Test combinations of time_cost and memory_cost
    candidates = [
        {"time_cost": 3, "memory_cost": 65536, "parallelism": 1, "hash_len": 32},  # 64 MiB
        {"time_cost": 4, "memory_cost": 48000, "parallelism": 1, "hash_len": 32},  # ~47 MiB
        {"time_cost": 8, "memory_cost": 19456, "parallelism": 1, "hash_len": 32},  # 19 MiB
        {"time_cost": 2, "memory_cost": 65536, "parallelism": 1, "hash_len": 32},
        {"time_cost": 3, "memory_cost": 32768, "parallelism": 1, "hash_len": 32},
    ]

    best_cfg = candidates[0]
    best_diff = float("inf")
    best_time = 0.0

    for cfg in candidates:
        t0 = time.perf_counter()
        hash_password("Argon2id", "benchmark_probe", **cfg)
        elapsed = time.perf_counter() - t0
        diff = abs(elapsed - target_sec)
        if diff < best_diff:
            best_diff = diff
            best_cfg = cfg
            best_time = elapsed

    mem_mib = best_cfg["memory_cost"] / 1024.0
    return {
        "tunable": True,
        "parameters": best_cfg,
        "target_ms": round(target_sec * 1000, 2),
        "measured_ms": round(best_time * 1000, 2),
        "notes": f"Argon2id hybrid memory/side-channel resistant with {mem_mib:.1f} MiB RAM, t={best_cfg['time_cost']}."
    }


def run_calibration(target_sec: float = 0.100) -> Dict[str, Any]:
    """Runs calibration across all algorithms and returns structured report."""
    print("=" * 60)
    print(f"CALIBRATION: Tuning slow algorithms to ~{target_sec*1000:.0f} ms defender cost")
    print("=" * 60)

    sys_info = get_system_info()
    print(f"Host CPU : {sys_info['cpu']} ({sys_info['cpu_arch']}, {sys_info['cpu_cores']} cores)")
    print(f"Host OS  : {sys_info['os']}")
    print(f"Python   : {sys_info['python_version']}")
    print("-" * 60)

    calibrated = {
        "MD5": calibrate_md5(),
        "SHA-256": calibrate_sha256(),
        "PBKDF2": calibrate_pbkdf2(target_sec),
        "bcrypt": calibrate_bcrypt(target_sec),
        "scrypt": calibrate_scrypt(target_sec),
        "Argon2id": calibrate_argon2id(target_sec),
    }

    for name, res in calibrated.items():
        if res["tunable"]:
            print(f"[{name:9s}] Calibrated -> {res['measured_ms']:6.2f} ms | Params: {res['parameters']}")
        else:
            print(f"[{name:9s}] Non-tunable -> {res['measured_ms']:8.4f} ms (Fixed digest complexity)")

    return {
        "system_info": sys_info,
        "target_defender_ms": target_sec * 1000,
        "calibrated_configs": calibrated,
        "owasp_baseline_configs": OWASP_CONFIGS,
    }


if __name__ == "__main__":
    result = run_calibration()
    print("\nCalibration output successfully generated.")
