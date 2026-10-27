"""
benchmark.py - Phase 2: Defender Cost-Normalized Guess-Rate Benchmark.

Measures single-process attacker guesses per second for each algorithm under:
1. Calibrated parameters (~100 ms defender cost)
2. OWASP baseline parameters
Repeats measurements 3 times per algorithm, computes mean and standard deviation,
computes the relative speedup ratio versus MD5, and renders a log-scale bar chart.
"""

import os
import sys
import time
import json
import numpy as np
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt

sys.path.append(os.path.dirname(__file__))
from algorithms import hash_password, OWASP_CONFIGS


def measure_single_rate(algo_name: str, params: dict, duration_target: float = 0.5, min_samples: int = 5) -> float:
    """
    Measures guesses/sec by running hashes until duration_target is met or min_samples completed.
    Returns: guesses_per_second
    """
    sample_pwd = "BenchmarkPassword123!"
    
    # Fast algorithms: run larger batch
    if algo_name in ["MD5", "SHA-256"]:
        batch = 50000
        t0 = time.perf_counter()
        for i in range(batch):
            hash_password(algo_name, f"{sample_pwd}_{i}", **params)
        elapsed = time.perf_counter() - t0
        return batch / max(elapsed, 1e-6)

    # Slow algorithms: run fixed count or until ~duration_target
    count = 0
    t0 = time.perf_counter()
    while True:
        hash_password(algo_name, f"{sample_pwd}_{count}", **params)
        count += 1
        elapsed = time.perf_counter() - t0
        if count >= min_samples and elapsed >= duration_target:
            break
        if count >= 30:  # Safety cap
            break
            
    return count / max(elapsed, 1e-6)


def run_benchmark(calibrated_configs: dict, quick_mode: bool = False, repetitions: int = 3) -> dict:
    """
    Runs 3 repetitions for each algorithm under both calibrated and OWASP configs.
    """
    target_dur = 0.2 if quick_mode else 0.5
    min_samples = 3 if quick_mode else 6

    print("\n" + "=" * 60)
    print(f"BENCHMARK: Measuring Guesses Per Second ({'QUICK' if quick_mode else 'FULL'} MODE)")
    print("=" * 60)

    results = {
        "calibrated": {},
        "owasp": {}
    }

    # 1. Calibrated suite
    print("\n--- 1. Calibrated Parameters (~100 ms Defender Cost) ---")
    for name in ["MD5", "SHA-256", "PBKDF2", "bcrypt", "scrypt", "Argon2id"]:
        cfg_entry = calibrated_configs.get(name, {})
        params = cfg_entry.get("parameters", {}) if isinstance(cfg_entry, dict) else {}
        
        rates = []
        for rep in range(repetitions):
            rate = measure_single_rate(name, params, duration_target=target_dur, min_samples=min_samples)
            rates.append(rate)
        
        mean_rate = float(np.mean(rates))
        std_rate = float(np.std(rates))
        
        results["calibrated"][name] = {
            "rates": rates,
            "mean_gps": mean_rate,
            "std_gps": std_rate,
            "params": params,
            "measured_latency_ms": (1000.0 / mean_rate) if mean_rate > 0 else 0.0
        }
        print(f"[{name:9s}] {mean_rate:12,.1f} guesses/s (±{std_rate:8,.1f}) | Avg Latency: {1000.0/mean_rate:8.3f} ms")

    # 2. OWASP baseline suite
    print("\n--- 2. OWASP Baseline Parameters ---")
    for name in ["MD5", "SHA-256", "PBKDF2", "bcrypt", "scrypt", "Argon2id"]:
        params = OWASP_CONFIGS.get(name, {})
        rates = []
        for rep in range(repetitions):
            rate = measure_single_rate(name, params, duration_target=target_dur, min_samples=min_samples)
            rates.append(rate)

        mean_rate = float(np.mean(rates))
        std_rate = float(np.std(rates))
        results["owasp"][name] = {
            "rates": rates,
            "mean_gps": mean_rate,
            "std_gps": std_rate,
            "params": params,
            "measured_latency_ms": (1000.0 / mean_rate) if mean_rate > 0 else 0.0
        }
        print(f"[{name:9s}] {mean_rate:12,.1f} guesses/s (±{std_rate:8,.1f}) | Avg Latency: {1000.0/mean_rate:8.3f} ms")

    # Compute speedup ratio versus MD5
    md5_cal_rate = results["calibrated"]["MD5"]["mean_gps"]
    md5_owasp_rate = results["owasp"]["MD5"]["mean_gps"]

    for name in results["calibrated"]:
        algo_rate = results["calibrated"][name]["mean_gps"]
        results["calibrated"][name]["ratio_vs_md5"] = float(md5_cal_rate / max(algo_rate, 1e-6))

    for name in results["owasp"]:
        algo_rate = results["owasp"][name]["mean_gps"]
        results["owasp"][name]["ratio_vs_md5"] = float(md5_owasp_rate / max(algo_rate, 1e-6))

    return results


def plot_guess_rates(benchmark_data: dict, output_path: str):
    """
    Renders a high-resolution, log-scale comparison bar chart.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    cal_data = benchmark_data["calibrated"]
    owasp_data = benchmark_data["owasp"]
    
    algos = ["MD5", "SHA-256", "PBKDF2", "bcrypt", "scrypt", "Argon2id"]
    cal_means = [cal_data[a]["mean_gps"] for a in algos]
    cal_stds = [cal_data[a]["std_gps"] for a in algos]
    owasp_means = [owasp_data[a]["mean_gps"] for a in algos]
    owasp_stds = [owasp_data[a]["std_gps"] for a in algos]
    
    x = np.arange(len(algos))
    width = 0.35

    # Aesthetic styling
    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
    fig, ax = plt.subplots(figsize=(10, 6), dpi=200)

    # Plot bars
    bars1 = ax.bar(x - width/2, cal_means, width, yerr=cal_stds, label="Calibrated (~100 ms defender cost)",
                   color="#2563eb", capsize=4, edgecolor="#1e3a8a", alpha=0.9)
    bars2 = ax.bar(x + width/2, owasp_means, width, yerr=owasp_stds, label="OWASP Baseline",
                   color="#059669", capsize=4, edgecolor="#064e3b", alpha=0.9)

    ax.set_yscale("log")
    ax.set_ylabel("Attacker Guesses per Second (log scale)", fontsize=12, fontweight="bold")
    ax.set_title("Single-Core Attacker Guess Rate by Algorithm & Configuration", fontsize=14, fontweight="bold", pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(algos, fontsize=11, fontweight="semibold")
    ax.legend(frameon=True, facecolor="#ffffff", framealpha=0.9, fontsize=10)
    ax.grid(True, which="both", ls="--", lw=0.5, alpha=0.6)

    # Annotate values on top of bars
    for bar in bars1:
        yval = bar.get_height()
        ax.annotate(f"{yval:,.0f}" if yval >= 10 else f"{yval:.1f}",
                    xy=(bar.get_x() + bar.get_width() / 2, yval),
                    xytext=(0, 4), textcoords="offset points",
                    ha="center", va="bottom", fontsize=8, rotation=35)

    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()
    print(f"\nSaved benchmark chart -> {output_path}")
