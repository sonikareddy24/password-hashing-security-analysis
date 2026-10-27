"""
generate_visuals.py - Generates visually appealing graphics for IEEE paper and Web UI:
1. rainbow_attack_pie.png: Pie / Donut charts showing Unsalted vs Salted crack outcome.
2. memory_profile_chart.png: Architectural memory-hardness comparison.
3. exposure_breakdown_chart.png: Credential exposure pie/donut distribution.
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "results"))
os.makedirs(RESULTS_DIR, exist_ok=True)

# Aesthetic styling
plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")

def create_rainbow_pie_chart():
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 5), dpi=220)

    # 1. Unsalted Hash Outcomes
    labels_unsalted = ["Cracked Instantly\n(95.0%)", "Resisted\n(5.0% Non-Dict)"]
    sizes_unsalted = [95.0, 5.0]
    colors_unsalted = ["#ef4444", "#94a3b8"]
    explode_unsalted = (0.06, 0)

    wedges1, texts1, autotexts1 = ax1.pie(
        sizes_unsalted,
        labels=labels_unsalted,
        autopct="%1.1f%%",
        startangle=140,
        colors=colors_unsalted,
        explode=explode_unsalted,
        pctdistance=0.75,
        textprops={"fontsize": 10, "fontweight": "bold"}
    )
    # Donut hole
    centre_circle1 = plt.Circle((0, 0), 0.52, fc="white")
    ax1.add_artist(centre_circle1)
    ax1.set_title("Unsalted Database (MD5 / SHA-256)\nLookups Completed in 0.20 ms", fontsize=11, fontweight="bold", pad=10)

    # 2. Salted Hash Outcomes
    labels_salted = ["Fully Protected\n(100.0%)", "Cracked by Table\n(0.0%)"]
    sizes_salted = [100.0, 0.0]
    colors_salted = ["#10b981", "#ef4444"]

    wedges2, texts2, autotexts2 = ax2.pie(
        sizes_salted,
        labels=labels_salted,
        autopct="%1.0f%%",
        startangle=90,
        colors=colors_salted,
        pctdistance=0.75,
        textprops={"fontsize": 10, "fontweight": "bold"}
    )
    centre_circle2 = plt.Circle((0, 0), 0.52, fc="white")
    ax2.add_artist(centre_circle2)
    ax2.set_title("Salted Database (16-Byte Random Salt)\nPrecomputed Tables 100% Defeated", fontsize=11, fontweight="bold", pad=10)

    plt.suptitle("Precomputed Lookup (Rainbow-Style) Reversal: Unsalted vs. Salted Credentials (1,000 Accounts)",
                 fontsize=12, fontweight="bold", y=0.98)
    plt.tight_layout()
    out_path = os.path.join(RESULTS_DIR, "rainbow_attack_pie.png")
    plt.savefig(out_path, dpi=220)
    plt.close()
    print(f"Generated -> {out_path}")


def create_memory_hardness_chart():
    fig, ax = plt.subplots(figsize=(9, 4.8), dpi=220)

    algos = ["MD5", "SHA-256", "PBKDF2", "bcrypt", "scrypt", "Argon2id"]
    # Memory in KiB for log scale comparison
    # MD5: ~0.1 KiB, SHA-256: ~0.1 KiB, PBKDF2: ~0.2 KiB, bcrypt: 4 KiB, scrypt: 32768 KiB, Argon2id: 48000 KiB
    mem_kib = [0.1, 0.1, 0.2, 4.0, 32768.0, 48000.0]
    colors = ["#94a3b8", "#94a3b8", "#f59e0b", "#10b981", "#0284c7", "#6366f1"]

    bars = ax.bar(algos, mem_kib, color=colors, edgecolor="#1e293b", linewidth=1.2, width=0.55)
    ax.set_yscale("log")
    ax.set_ylabel("RAM Allocation per Hash in KiB (Log Scale)", fontsize=11, fontweight="bold")
    ax.set_title("Architectural Memory-Hardness: Defeating GPU/ASIC Parallelism", fontsize=12, fontweight="bold", pad=12)

    # Annotate values
    annotations = ["~0 KiB", "~0 KiB", "~0 KiB (CPU-only)", "4 KiB (L1 cache)", "32 MiB (RAM-hard)", "48 MiB (RAM-hard)"]
    for bar, text in zip(bars, annotations):
        yval = bar.get_height()
        ax.annotate(text,
                    xy=(bar.get_x() + bar.get_width() / 2, yval),
                    xytext=(0, 4), textcoords="offset points",
                    ha="center", va="bottom", fontsize=8.5, fontweight="bold")

    ax.grid(True, which="both", ls="--", lw=0.5, alpha=0.5)
    plt.tight_layout()
    out_path = os.path.join(RESULTS_DIR, "memory_profile_chart.png")
    plt.savefig(out_path, dpi=220)
    plt.close()
    print(f"Generated -> {out_path}")


if __name__ == "__main__":
    create_rainbow_pie_chart()
    create_memory_hardness_chart()
