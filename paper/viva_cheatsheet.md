# Viva Voce & Oral Defense Cheatsheet
## Project: Cost-Normalized Password Hashing Benchmark & Salting Analysis
**Extension of Skanda et al. (IEEE NKCon 2022)**

---

## 1. The 60-Second Elevator Pitch
> *"Our project extends the 2022 IEEE paper by Skanda et al., which compared MD5, SHA-256, and bcrypt for password storage. We addressed its three main limitations: first, we added modern standards—PBKDF2, scrypt, and Argon2id; second, we normalized all slow algorithms to an equal defender cost of approximately 100 milliseconds per login on our server; and third, we empirically proved that rainbow table and precomputed lookup attacks are defeated by per-user salts, not by bcrypt alone. On an Apple M1 processor, our cost-normalized algorithms reduced single-core attacker guessing speed from 1.5 million guesses/second (MD5) down to 8 to 15 guesses/second—a slowdown factor exceeding 100,000x. When per-user salts were added, precomputed lookup tables suffered a 0.0% match rate, increasing attacker compute time by over 10^9x for bcrypt."*

---

## 2. Walkthrough of Every Code File

| File | Purpose | Key Functions / Details |
| :--- | :--- | :--- |
| **`src/algorithms.py`** | Unified interface for all 6 hashing schemes. | Implements `hash(password, salt)` and `verify(password, stored)`. Formats output in modular crypt format (e.g. `$pbkdf2$`, `$2b$`, `$scrypt$`, `$argon2id$`). |
| **`src/calibrate.py`** | Phase 1: Machine Calibration. | Finds parameter settings where PBKDF2, bcrypt, scrypt, and Argon2id each take ~100 ms on the local CPU. Profiles sub-microsecond non-tunable MD5 & SHA-256. |
| **`src/benchmark.py`** | Phase 2: Guess-Rate Benchmark. | Measures attacker guesses/second over 3 trials for each algorithm (calibrated & OWASP configs). Computes mean, standard deviation, and ratio vs. MD5. Plots log-scale bar chart. |
| **`src/rainbow_demo.py`** | Phase 3: Precomputed Lookup Demo. | Builds precomputed hash lookup tables for MD5 and SHA-256. Proves unsalted hashes are cracked in 0.03 ms (94.8%), while salted hashes give 0.0% matches. |
| **`src/attack_sim.py`** | Phase 4: Attack Simulation. | Runs real verified crack on small subset (proves engine works). Projects long-term exposure curves across 220 accounts ($T = \text{rank} / \text{rate}$). Plots percentage cracked vs. log time. |
| **`src/bcrypt_limit.py`** | Phase 5: Bcrypt 72-Byte Boundary. | Demonstrates that bcrypt only uses the first 72 bytes. Catches `ValueError` in modern Python `bcrypt` 5.0.0, shows legacy collisions, and proves SHA-256 pre-hashing fix. |
| **`src/wordlist.py`** | Dataset Manager. | Loads `data/rockyou.txt` if present; otherwise generates deterministic `data/synthetic_wordlist.txt` (30,000 realistic breach-style mutated passwords). |
| **`src/run_all.py`** | Master Suite Orchestrator. | Supports `--quick` (< 2 mins) and `--full` (< 10 mins). Runs all 5 phases, saves `results/results.json`, and exports PNG charts. |
| **`web/app.py`** | Flask Backend Server. | Provides REST APIs: `/api/results`, `/api/hash` (Live Hash Lab), and `/api/lookup` (Rainbow Table Demo). |
| **`web/static/`** | Frontend Web UI. | Single-page app with light/dark theme toggle, "Explain simply" viva toggle, responsive cards, and dynamic charts. |

---

## 3. Top 15 Likely Professor Questions & Model Answers

### Q1: Why did you choose 100 milliseconds as the defender cost target?
**Model Answer:**  
> *"In production web authentication, 100 ms represents the industry standard threshold recommended by OWASP. It is fast enough that a legitimate user logging in experiences zero noticeable delay, but slow enough that an attacker attempting to brute-force millions of passwords on a stolen database is severely throttled."*

### Q2: Why can't we just use SHA-256 with a salt? Why do we need PBKDF2, bcrypt, or Argon2id?
**Model Answer:**  
> *"A salt only prevents precomputed dictionary and rainbow table attacks; it does NOT prevent online or offline brute-force guessing! SHA-256 is designed to be as fast as possible for message integrity (executing in 0.0006 milliseconds, or over 1.5 million hashes per second per core). On modern consumer GPUs (like an NVIDIA RTX 4090), an attacker can compute over 10 billion SHA-256 hashes per second. With salted SHA-256, an attacker can still crack an 8-character password in minutes. Key stretching algorithms like Argon2id force the attacker to perform thousands of mathematical rounds and allocate tens of megabytes of RAM per guess."*

### Q3: What is "memory hardness" and why does it matter against GPUs and ASICs?
**Model Answer:**  
> *"CPUs have large, flexible caches and access to gigabytes of system RAM, but only a few dozen cores. GPUs have thousands of small cores designed for parallel math, but very small local memory cache per core. Algorithms like PBKDF2 are purely CPU-bound (registers only), so GPUs can run thousands in parallel. In contrast, memory-hard algorithms like scrypt and Argon2id require 32 to 64 megabytes of RAM for every single hash calculation. Because thousands of GPU cores cannot access that much memory simultaneously without hitting a memory-bus bottleneck, memory hardness completely strips GPUs and custom ASICs of their parallel speed advantage."*

### Q4: Skanda et al. claimed bcrypt is best because rainbow tables failed on it. What was wrong with that conclusion?
**Model Answer:**  
> *"Skanda et al. attributed rainbow table resistance as a special property of bcrypt itself. In reality, rainbow tables fail against bcrypt solely because bcrypt automatically enforces a 16-byte random salt. When we added an identical salt to MD5, precomputed rainbow lookups also failed with a 0.0% success rate! Furthermore, Skanda et al. omitted modern memory-hard standards like Argon2id, which won the Password Hashing Competition and provides superior protection without bcrypt's 72-byte limitation."*

### Q5: What is the difference between a true rainbow table and the dictionary lookup table in your demo?
**Model Answer:**  
> *"A dictionary lookup table stores every `hash -> password` pair directly in memory or disk, giving O(1) lookup time but requiring huge disk space (gigabytes or terabytes). A true rainbow table (invented by Philippe Oechslin) uses reduction functions `R(h)` to chain thousands of hashes together, storing only the start and end of each chain. This compresses storage by 99% at the expense of needing extra computation to regenerate chains during a lookup. We implemented a dictionary table because it represents the theoretical best-case bound of precomputed attacks (instant lookup). Because both rainbow tables and lookup tables require static, unsalted hashes, per-user salting completely destroys both."*

### Q6: Why did you project the attack curve instead of cracking all 220 passwords for real?
**Model Answer:**  
> *"Doing a full offline crack of 220 passwords against slow algorithms at 100 ms per hash would require over 10 days of continuous CPU time! That is computationally wasteful and impractical for an educational project. The academically accepted method is two-fold: first, we ran a real, verified offline dictionary attack on a small subset (top candidates) to empirically prove that our cracker works across all 6 algorithms; second, we used the exact formula `Time = Rank / Measured_Guesses_Per_Sec` to project the full curve. This gives 100% mathematically sound exposure curves in seconds."*

### Q7: What is the bcrypt 72-byte edge case?
**Model Answer:**  
> *"Bcrypt is based on Bruce Schneier's Blowfish cipher, whose internal key schedule accepts a maximum key length of 72 bytes (576 bits). In classic OpenBSD bcrypt, any characters after byte 72 are silently discarded! For example, `PasswordA * 72 + 'Suffix1'` and `PasswordA * 72 + 'Suffix2'` produce the exact same bcrypt hash and will verify as equal. In modern Python `bcrypt` 5.0.0, the library detects inputs over 72 bytes and raises an explicit `ValueError`. The OWASP recommended mitigation is either to pre-hash the password with SHA-256 before bcrypt, or to migrate to Argon2id, which supports passwords up to 4 gigabytes."*

### Q8: What is the difference between Argon2d, Argon2i, and Argon2id?
**Model Answer:**  
> - **Argon2d:** Uses data-dependent memory access. It provides maximum resistance against GPU/ASIC cracking, but is vulnerable to side-channel timing attacks. Best for proof-of-work/cryptocurrencies.  
> - **Argon2i:** Uses data-independent memory access. It is completely immune to side-channel cache-timing attacks, but slightly less resistant to GPU attacks. Best for password hashing when side-channel attacks are a concern.  
> - **Argon2id:** A hybrid combination! It uses data-independent access for the first pass (defeating side channels) and data-dependent access for later passes (defeating GPUs). It is the recommended mode in IETF RFC 9106 and OWASP.

### Q9: Why are your guess rates much lower than numbers reported in Hashcat benchmarks?
**Model Answer:**  
> *"Our benchmarks were conducted on a single CPU core in pure Python. Tools like Hashcat use heavily optimized assembly/C code running on clusters of dedicated GPUs (like 8x NVIDIA RTX 4090s). On GPUs, MD5 reaches over 100 billion guesses/second! Therefore, we explicitly state in our paper that our CPU-only numbers represent an absolute lower bound on real-world attacker capabilities."*

### Q10: Where is the salt stored? Doesn't the attacker get the salt if they steal the database?
**Model Answer:**  
> *"Yes! The salt is not a secret key; it is stored in plaintext right alongside the hash in the database (e.g. in modular crypt format `$argon2id$v=19$m=48000,t=4,p=1$salt$hash`). The salt's purpose is not to hide data, but to ensure uniqueness. Because every user has a different random salt, an attacker cannot crack 1,000 users with one computation; they must crack each user individually from scratch, multiplying their total workload by the number of users in the database."*

### Q11: What is a "pepper" and how does it differ from a salt?
**Model Answer:**  
> *"A salt is unique per user, random, and stored openly in the database. A pepper is a secret cryptographic key (e.g., an HMAC key or encryption key) shared across all passwords and stored externally—such as in a Hardware Security Module (HSM) or separate secrets manager. If an attacker only dumps the SQL database, they cannot verify guesses without the external pepper."*

### Q12: Why did MD5 and SHA-256 have identical execution times in your calibration table?
**Model Answer:**  
> *"Both MD5 and SHA-256 execute so fast on modern hardware (around 600 nanoseconds, or 0.0006 milliseconds) that the measurement reaches the resolution limit of standard OS process timers and Python function call overhead. Neither has an iteration counter, so neither can be tuned to 100 ms."*

### Q13: If bcrypt is vulnerable to the 72-byte limit, why is it still so popular?
**Model Answer:**  
> *"Bcrypt was introduced in 1999 (Provos and Mazières) and has survived over 25 years of cryptanalysis without any practical mathematical break. It is built into OpenBSD, Ruby on Rails, Django, and Node.js. It remains secure for passwords under 72 characters, but Argon2id is now preferred for new designs."*

### Q14: How did you ensure your benchmark experiments were ethical?
**Model Answer:**  
> *"All experiments ran 100% locally on our machine with zero network requests. We used only synthetic rule-mutated candidate passwords and simulated accounts. We did not target, probe, or interact with any external networks, production servers, or real human user credentials."*

### Q15: What final recommendation would you give to a software architect building an authentication system today?
**Model Answer:**  
> *"Use Argon2id (RFC 9106) with at least 19 to 48 MiB of memory, time cost 2 to 4, parallelism 1, and a unique 16-byte random salt per user. Tune the parameters so the login takes approximately 100 ms on your production server. If constrained by a legacy FIPS-compliant environment where Argon2id is not yet approved, use PBKDF2-HMAC-SHA256 with at least 600,000 iterations."*

---

## 4. Key Metrics to Memorize for the Viva

- **Target defender latency:** ~100 ms (0.100 s)
- **MD5 single-core guess rate:** ~1,487,000 guesses/sec (0.0007 ms)
- **SHA-256 single-core guess rate:** ~1,545,000 guesses/sec (0.0006 ms)
- **PBKDF2 calibrated rate:** 10.2 guesses/sec (840,000 iterations, 97.7 ms)
- **bcrypt calibrated rate:** 8.6 guesses/sec (cost 11, 116.1 ms)
- **scrypt calibrated rate:** 14.7 guesses/sec (N=32,768, 67.9 ms, 32 MiB RAM)
- **Argon2id calibrated rate:** 9.4 guesses/sec (t=4, m=48,000 KiB, 105.9 ms, 47 MiB RAM)
- **Slowdown factor vs MD5:** Over **100,000x** (up to 172,000x for bcrypt)
- **Precomputed lookup time per user:** 0.12 microseconds (0.030 ms for 250 users)
- **Unsalted lookup success rate:** **94.8%**
- **Salted lookup success rate:** **0.0%** (table rendered completely useless)
- **Speedup of lookup over salted bcrypt:** Over **2.39 billion times (2.39 x 10^9)**
- **Bcrypt limit:** Exactly **72 bytes**
