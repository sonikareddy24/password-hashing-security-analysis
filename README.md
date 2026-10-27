# Cost-Normalized Comparison of Password Hashing Algorithms and the Effect of Salting on Rainbow-Table Attacks

**An Academic Extension of Skanda et al. (IEEE NKCon 2022)**

---

## 1. Project Overview

This repository contains an academic research benchmark evaluating password storage security. It directly replicates and extends the study by:
> **Base Paper:** Skanda, Srivatsa, and Premananda, *"Secure Hashing using BCrypt for Cryptographic Applications,"* in 2022 IEEE North Karnataka Subsection Flagship International Conference (NKCon), pp. 1-5.

### Research Question
> *"When MD5, SHA-256, PBKDF2, bcrypt, scrypt, and Argon2id are tuned to the same defender cost (~100 ms per hash on one machine), how many guesses per second can an attacker make, how much faster is a precomputed lookup attack on unsalted vs. salted hashes, and what fraction of a realistic password set is exposed over time?"*

### Key Extensions Over the Base Paper
1. **Broader Algorithm Coverage:** Expands the original 3 algorithms (MD5, SHA-256, bcrypt) to include **PBKDF2-HMAC-SHA256**, **scrypt**, and **Argon2id** (the IETF RFC 9106 modern standard).
2. **Defender Cost Normalization:** Rather than testing algorithms at arbitrary default settings, we calibrate each slow algorithm to an identical defender latency of **~100 ms** per login on the host CPU.
3. **Mathematical Proof of Salting:** Demonstrates that rainbow tables and precomputed lookup attacks fail against salted hashes as a mathematical certainty (0.0% recovery), not as an algorithm-specific property of bcrypt.
4. **Realistic Attack Projections:** Combines a verified real dictionary crack with an analytical Zipf-distributed exposure curve across 220 realistic accounts.
5. **Bcrypt 72-Byte Boundary:** Empirically proves the 72-byte ceiling in bcrypt and demonstrates SHA-256 pre-hashing mitigations.

---

## 2. Assumptions and Sensible Defaults

In accordance with autonomous research guidelines, the following design assumptions were made and implemented:
1. **Defender Latency Target (100 ms):** Based on OWASP guidelines, 100 ms represents the optimal tradeoff between legitimate login latency and cryptographic brute-force defense.
2. **Wordlist Policy:** As per ethical guidelines, no external files were downloaded automatically. If `data/rockyou.txt` is present, the top 100,000 entries are used. Otherwise, the system automatically generates a deterministic, rule-mutated `data/synthetic_wordlist.txt` (30,000 entries combining top breach passwords, dictionary words, capitalization, leet speak, and numeric suffixes).
3. **Precomputed Lookup Implementation:** An in-memory hash dictionary table ($O(1)$ lookup) was implemented to demonstrate the theoretical upper bound of rainbow-table attacks. As both true rainbow chains and dictionary tables require static unsalted hashes, per-user salting neutralizes both with mathematical equivalence.
4. **Single-Core CPU Baseline:** Measurements are executed in single-core Python to guarantee reproducibility. We explicitly note in the paper that these numbers represent an absolute *lower bound* on adversary capabilities compared to multi-GPU cracking rigs (Hashcat).

---

## 3. Quick Start (3 Commands)

Execute the following commands in your terminal:

```bash
# 1. Activate virtual environment and install dependencies
python3 -m venv venv && source venv/bin/activate
pip install -r password-hash-benchmark/requirements.txt

# 2. Run the complete benchmark suite (Quick Mode: ~20 seconds; or use --full for maximum precision)
python password-hash-benchmark/src/run_all.py --quick

# 3. Launch the interactive Web UI and open in browser
python password-hash-benchmark/web/app.py
```
Open **http://127.0.0.1:5001** in your browser.

---

## 4. Project Structure

```
password-hash-benchmark/
├── README.md                     # Complete project documentation and assumptions
├── requirements.txt              # Minimal allowed dependencies (bcrypt, argon2-cffi, flask, matplotlib, pandas, numpy)
├── data/
│   └── synthetic_wordlist.txt    # 30,000 realistic breach-style mutated passwords
├── src/
│   ├── algorithms.py             # Unified interface: hash() & verify() for all 6 schemes
│   ├── calibrate.py              # Phase 1: Calibrates slow algorithms to ~100 ms defender cost
│   ├── benchmark.py              # Phase 2: Measures guesses/sec and generates log-scale chart
│   ├── rainbow_demo.py           # Phase 3: Unsalted vs salted precomputed lookup attack
│   ├── attack_sim.py             # Phase 4: Verified real crack + projected exposure curves
│   ├── bcrypt_limit.py           # Phase 5: 72-byte truncation boundary & OWASP mitigation
│   ├── wordlist.py               # Wordlist loader & synthetic dataset generator
│   └── run_all.py                # Master orchestrator (--quick / --full)
├── results/
│   ├── results.json              # Full structured benchmark dataset & machine specs
│   ├── guess_rate_comparison.png # Publication-ready log-scale guess rate chart
│   └── attack_curve_comparison.png# Exposure % vs time chart
├── web/
│   ├── app.py                    # Flask server with /api/hash, /api/lookup, /api/results
│   └── static/
│       ├── index.html            # Clean single-page responsive UI with dark mode & viva mode
│       ├── style.css             # Vanilla CSS design system & animations
│       └── app.js                # Frontend state management & live charts
└── paper/
    ├── paper.md                  # IEEE conference paper in Markdown (real empirical numbers)
    ├── paper.tex                 # IEEEtran two-column LaTeX source
    └── viva_cheatsheet.md        # Comprehensive oral defense preparation & top 15 Q&As
```

---

## 5. Experimental Results Summary (Apple M1 ARM64)

### A. Cost-Normalized Guess Rates (~100 ms Defender Latency)
| Algorithm | Defender Latency | Attacker Guess Rate | Slowdown vs. MD5 | Memory Overhead |
| :--- | :---: | :---: | :---: | :---: |
| **MD5** | 0.0007 ms | **1,487,475.1 guesses/s** | $1.0\times$ | Negligible |
| **SHA-256** | 0.0006 ms | **1,545,405.2 guesses/s** | $0.96\times$ | Negligible |
| **PBKDF2-HMAC-SHA256** | 97.67 ms | **10.2 guesses/s** | **$145,283.4\times$ slower** | Negligible |
| **bcrypt** ($c=11$) | 116.11 ms | **8.6 guesses/s** | **$172,709.6\times$ slower** | 4 KiB |
| **scrypt** ($N=32k$) | 67.88 ms | **14.7 guesses/s** | **$100,969.4\times$ slower** | 32.0 MiB |
| **Argon2id** ($m=48\text{M}, t=4$) | 105.88 ms | **9.4 guesses/s** | **$157,498.7\times$ slower** | 46.9 MiB |

### B. Effect of Salting on Precomputed Lookup Attacks
- **Unsalted Hashes:** 94.8% of user accounts cracked in **0.030 milliseconds** (0.12 $\mu$s per account).
- **Salted Hashes (16-byte random salt):** **0.0% cracked** (0 matches). Precomputed tables are rendered completely useless.
- **Speedup Ratio:** Precomputed lookups against unsalted storage are **$2.39 \times 10^9\times$ faster** than online brute-forcing salted bcrypt.

---

## 6. Ethics & Safety Statement

This software is developed strictly for local educational and research purposes. All experiments were conducted locally with simulated credentials and public wordlist heuristics. No network services, third-party systems, or real user accounts were probed or compromised.
