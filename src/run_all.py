"""
run_all.py - Master Orchestrator for Password Hashing Benchmark Suite.

Supports:
  --quick : Fast execution (< 2 minutes) for testing and rapid verification
  --full  : Comprehensive academic benchmark (< 10 minutes) with higher sample counts

Writes:
  results/results.json
  results/guess_rate_comparison.png
  results/attack_curve_comparison.png
"""

import os
import sys
import time
import json
import argparse
from typing import Dict, Any

# Ensure local imports work cleanly
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
sys.path.append(SCRIPT_DIR)

from calibrate import run_calibration
from benchmark import run_benchmark, plot_guess_rates
from rainbow_demo import run_rainbow_experiment
from attack_sim import run_attack_simulation, plot_attack_curves
from bcrypt_limit import demonstrate_bcrypt_limit


def main():
    parser = argparse.ArgumentParser(description="Password Hashing Benchmark Suite (Skanda et al. Extension)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--quick", action="store_true", default=False, help="Fast run (< 2 mins) for testing")
    group.add_argument("--full", action="store_true", default=False, help="Full benchmark (< 10 mins) with maximum precision")
    parser.add_argument("--target-ms", type=float, default=100.0, help="Target defender latency in milliseconds (default: 100.0)")
    
    args = parser.parse_args()
    
    # Default to quick if neither flag provided, or prompt flag
    is_quick = True
    if args.full:
        is_quick = False
    elif args.quick:
        is_quick = True
    else:
        print("[Notice] Neither --quick nor --full specified. Defaulting to --quick mode.")

    mode_label = "QUICK" if is_quick else "FULL"
    target_sec = args.target_ms / 1000.0

    print("=" * 70)
    print("PASSWORD HASHING BENCHMARK SUITE: EXTENSION OF SKANDA ET AL. (2022)")
    print(f"Mode: {mode_label} | Target Defender Cost: {args.target_ms:.1f} ms")
    print(f"Execution Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    start_total_time = time.perf_counter()

    results_dir = os.path.join(PROJECT_ROOT, "results")
    os.makedirs(results_dir, exist_ok=True)

    # -------------------------------------------------------------
    # PHASE 1: Calibration
    # -------------------------------------------------------------
    cal_data = run_calibration(target_sec=target_sec)

    # -------------------------------------------------------------
    # PHASE 2: Guess-Rate Benchmark
    # -------------------------------------------------------------
    bench_data = run_benchmark(cal_data["calibrated_configs"], quick_mode=is_quick, repetitions=3)
    bench_chart_path = os.path.join(results_dir, "guess_rate_comparison.png")
    plot_guess_rates(bench_data, bench_chart_path)

    # Extract calibrated guess rates for attack projection
    calibrated_rates = {
        algo: bench_data["calibrated"][algo]["mean_gps"]
        for algo in bench_data["calibrated"]
    }

    # -------------------------------------------------------------
    # PHASE 3: Rainbow / Precomputed Lookup-Table Experiment
    # -------------------------------------------------------------
    rainbow_data = run_rainbow_experiment(quick_mode=is_quick, guess_rates=calibrated_rates)

    # -------------------------------------------------------------
    # PHASE 4: Dictionary Attack Simulation & Exposure Projection
    # -------------------------------------------------------------
    attack_data = run_attack_simulation(cal_data["calibrated_configs"], calibrated_rates, quick_mode=is_quick)
    attack_chart_path = os.path.join(results_dir, "attack_curve_comparison.png")
    plot_attack_curves(attack_data["exposure_projection"], attack_chart_path)

    # -------------------------------------------------------------
    # PHASE 5: Bcrypt 72-Byte Limitation
    # -------------------------------------------------------------
    bcrypt_edge_data = demonstrate_bcrypt_limit()

    # -------------------------------------------------------------
    # Consolidate and Save results.json
    # -------------------------------------------------------------
    total_elapsed = time.perf_counter() - start_total_time

    final_results = {
        "metadata": {
            "title": "Cost-Normalized Comparison of Password Hashing Algorithms and the Effect of Salting on Rainbow-Table Attacks",
            "base_paper": "Skanda, Srivatsa, Premananda, IEEE NKCon 2022",
            "execution_mode": mode_label,
            "total_benchmark_time_seconds": round(total_elapsed, 2),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "system_info": cal_data["system_info"],
            "target_defender_ms": args.target_ms,
        },
        "phase1_calibration": {
            "calibrated_configs": cal_data["calibrated_configs"],
            "owasp_baseline_configs": cal_data["owasp_baseline_configs"],
        },
        "phase2_benchmark": bench_data,
        "phase3_rainbow_experiment": rainbow_data,
        "phase4_attack_simulation": attack_data,
        "phase5_bcrypt_limit": bcrypt_edge_data,
        "artifacts": {
            "guess_rate_chart": "results/guess_rate_comparison.png",
            "attack_curve_chart": "results/attack_curve_comparison.png",
        }
    }

    json_path = os.path.join(results_dir, "results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(final_results, f, indent=2)

    print("\n" + "=" * 70)
    print("BENCHMARK EXECUTION COMPLETE")
    print(f"Total Elapsed Time: {total_elapsed:.2f} seconds")
    print(f"Saved Structured Data -> {json_path}")
    print(f"Saved Rate Chart       -> {bench_chart_path}")
    print(f"Saved Exposure Chart   -> {attack_chart_path}")
    print("=" * 70)

    # Print summary table for student presentation
    print("\nSUMMARY TABLE FOR VIVA / DEFENSE:")
    print("-" * 75)
    print(f"{'Algorithm':10s} | {'Latency (ms)':12s} | {'Guesses / sec':14s} | {'Ratio vs MD5':14s} | {'Memory (RAM)'}")
    print("-" * 75)
    mem_notes = {
        "MD5": "Negligible",
        "SHA-256": "Negligible",
        "PBKDF2": "Negligible",
        "bcrypt": "4 KiB",
        "scrypt": "32 MiB",
        "Argon2id": "48 MiB",
    }
    for algo in ["MD5", "SHA-256", "PBKDF2", "bcrypt", "scrypt", "Argon2id"]:
        lat = bench_data["calibrated"][algo]["measured_latency_ms"]
        gps = bench_data["calibrated"][algo]["mean_gps"]
        ratio = bench_data["calibrated"][algo]["ratio_vs_md5"]
        mem = mem_notes.get(algo, "-")
        print(f"{algo:10s} | {lat:10.2f} ms | {gps:12,.1f}  | {ratio:12,.1f}x | {mem}")
    print("-" * 75)


if __name__ == "__main__":
    main()
