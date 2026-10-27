/**
 * app.js - Client-side interactivity for Password Hashing Benchmark Suite.
 * Handles tab navigation, theme toggling, plain-English mode, Live Hash Lab,
 * Rainbow Table attack simulation, and results data rendering.
 */

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initTabs();
  initLiveHashLab();
  initRainbowDemo();
  loadBenchmarkResults();
});

/* ==========================================================================
   1. Theme Management (Light / Dark Mode)
   ========================================================================== */

function initTheme() {
  const themeToggle = document.getElementById("themeToggle");
  const savedTheme = localStorage.getItem("theme") || 
    (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");

  document.documentElement.setAttribute("data-theme", savedTheme);
  updateThemeButton(savedTheme);

  if (themeToggle) {
    themeToggle.addEventListener("click", () => {
      const currentTheme = document.documentElement.getAttribute("data-theme");
      const newTheme = currentTheme === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", newTheme);
      localStorage.setItem("theme", newTheme);
      updateThemeButton(newTheme);
    });
  }
}

function updateThemeButton(theme) {
  const btn = document.getElementById("themeToggle");
  if (btn) {
    btn.innerHTML = theme === "dark" ? "☀️ Light Mode" : "🌙 Dark Mode";
  }
}

/* ==========================================================================
   2. Navigation Tabs
   ========================================================================== */

function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  const panels = document.querySelectorAll(".tab-panel");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");

      tabBtns.forEach(b => b.classList.remove("active"));
      panels.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const targetPanel = document.getElementById(targetId);
      if (targetPanel) {
        targetPanel.classList.add("active");
      }
    });
  });
}

function initLiveHashLab() {
  const input = document.getElementById("hashPasswordInput");
  const hashBtn = document.getElementById("hashSubmitBtn");
  const container = document.getElementById("hashCardsContainer");

  if (!hashBtn || !input) return;

  const computeHashes = async () => {
    const password = input.value.trim() || "Password123!";
    hashBtn.disabled = true;
    hashBtn.textContent = "Computing Hashes...";

    try {
      const response = await fetch("/api/hash", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password })
      });
      const data = await response.json();

      if (data.status === "success") {
        renderHashCards(data.results, container);
      }
    } catch (err) {
      console.error("Hash calculation failed:", err);
      container.innerHTML = `<div class="card"><p style="color:var(--accent-rose)">Error communicating with backend: ${err.message}</p></div>`;
    } finally {
      hashBtn.disabled = false;
      hashBtn.textContent = "Hash Again (Observe Salts)";
    }
  };

  hashBtn.addEventListener("click", computeHashes);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") computeHashes();
  });

  // Run initial hash computation
  computeHashes();
}

function renderHashCards(results, container) {
  container.innerHTML = "";

  results.forEach(item => {
    const card = document.createElement("div");
    card.className = "hash-card";

    const badgeClass = item.is_salted ? "badge-success" : "badge-danger";
    const badgeText = item.is_salted ? "Salted (Unique Each Time)" : "Unsalted (Static)";

    card.innerHTML = `
      <div>
        <div class="hash-card-header">
          <span class="algo-tag">${item.algorithm}</span>
          <span class="latency-badge">${item.time_ms.toFixed(2)} ms</span>
        </div>
        <div style="margin-bottom: 0.5rem;">
          <span class="badge ${badgeClass}">${badgeText}</span>
          ${item.memory_hard ? '<span class="badge badge-info" style="margin-left:4px;">Memory-Hard</span>' : ''}
        </div>
        <div class="hash-value-box" title="Click to copy">${escapeHtml(item.hash)}</div>
      </div>
      <div>
        <p class="hash-meta">${escapeHtml(item.explanation)}</p>
      </div>
    `;

    // Click to copy hash
    const box = card.querySelector(".hash-value-box");
    box.addEventListener("click", () => {
      navigator.clipboard.writeText(item.hash).then(() => {
        const orig = box.textContent;
        box.textContent = "Copied to clipboard!";
        box.style.color = "var(--accent-green)";
        setTimeout(() => {
          box.textContent = orig;
          box.style.color = "";
        }, 1200);
      });
    });

    container.appendChild(card);
  });
}

/* ==========================================================================
   5. Rainbow Table Demo Section
   ========================================================================== */

function initRainbowDemo() {
  const unsaltedBtn = document.getElementById("attackUnsaltedBtn");
  const saltedBtn = document.getElementById("attackSaltedBtn");
  const progressBar = document.getElementById("rainbowProgressBar");
  const statusBox = document.getElementById("rainbowStatusBox");
  const tableBody = document.getElementById("rainbowResultsTableBody");

  if (!unsaltedBtn || !saltedBtn) return;

  const runAttack = async (type) => {
    unsaltedBtn.disabled = true;
    saltedBtn.disabled = true;
    statusBox.textContent = `Running precomputed lookup attack against ${type} password hashes...`;
    progressBar.style.width = "20%";
    progressBar.className = "progress-bar";

    try {
      const response = await fetch("/api/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attack_type: type, sample_size: 500 })
      });
      const data = await response.json();

      progressBar.style.width = "100%";
      if (type === "salted") {
        progressBar.classList.add("salted-success");
      }

      statusBox.innerHTML = `<strong>Result:</strong> ${data.message} (Lookup completed across ${data.sample_size} accounts in ${data.md5_result.total_time_seconds * 1000} ms)`;

      // Populate summary row in results table
      const md5 = data.md5_result;
      const sha = data.sha256_result;

      tableBody.innerHTML = `
        <tr>
          <td><strong>MD5 (${type.toUpperCase()})</strong></td>
          <td>${data.sample_size}</td>
          <td>${md5.cracked_count}</td>
          <td><span class="badge ${md5.crack_percentage > 50 ? 'badge-danger' : 'badge-success'}">${md5.crack_percentage}%</span></td>
          <td>${(md5.total_time_seconds * 1000).toFixed(3)} ms</td>
          <td>${type === 'unsalted' ? 'Instant O(1) Dictionary Match' : 'Defeated (0% hit)'}</td>
        </tr>
        <tr>
          <td><strong>SHA-256 (${type.toUpperCase()})</strong></td>
          <td>${data.sample_size}</td>
          <td>${sha.cracked_count}</td>
          <td><span class="badge ${sha.crack_percentage > 50 ? 'badge-danger' : 'badge-success'}">${sha.crack_percentage}%</span></td>
          <td>${(sha.total_time_seconds * 1000).toFixed(3)} ms</td>
          <td>${type === 'unsalted' ? 'Instant O(1) Dictionary Match' : 'Defeated (0% hit)'}</td>
        </tr>
      `;
    } catch (err) {
      statusBox.textContent = `Attack simulation error: ${err.message}`;
    } finally {
      unsaltedBtn.disabled = false;
      saltedBtn.disabled = false;
    }
  };

  unsaltedBtn.addEventListener("click", () => runAttack("unsalted"));
  saltedBtn.addEventListener("click", () => runAttack("salted"));
}

/* ==========================================================================
   6. Load Results from results.json
   ========================================================================== */

async function loadBenchmarkResults() {
  const container = document.getElementById("benchmarkTableBody");
  const systemBox = document.getElementById("systemInfoBadge");
  if (!container) return;

  try {
    const res = await fetch("/api/results");
    if (!res.ok) {
      container.innerHTML = `<tr><td colspan="6">Run <code>python src/run_all.py --quick</code> to generate results.json</td></tr>`;
      return;
    }
    const json = await res.json();
    const data = json.data;

    if (systemBox && data.metadata && data.metadata.system_info) {
      const s = data.metadata.system_info;
      systemBox.textContent = `${s.cpu} (${s.cpu_arch}) | Python ${s.python_version} | ${data.metadata.execution_mode} Mode (${data.metadata.total_benchmark_time_seconds}s)`;
    }

    // Populate Calibrated Benchmark Table
    const cal = data.phase2_benchmark.calibrated;
    const algos = ["MD5", "SHA-256", "PBKDF2", "bcrypt", "scrypt", "Argon2id"];

    const memMap = {
      "MD5": "Negligible",
      "SHA-256": "Negligible",
      "PBKDF2": "Negligible (CPU only)",
      "bcrypt": "4 KiB (L1 Cache)",
      "scrypt": "32 MiB (Memory Hard)",
      "Argon2id": "48 MiB (RAM Hard + Side-channel resistant)"
    };

    let rows = "";
    algos.forEach(name => {
      const item = cal[name];
      const lat = item.measured_latency_ms.toFixed(2);
      const gps = item.mean_gps.toLocaleString(undefined, { maximumFractionDigits: 1 });
      const ratio = item.ratio_vs_md5.toLocaleString(undefined, { maximumFractionDigits: 1 });
      const mem = memMap[name];

      rows += `
        <tr>
          <td><strong>${name}</strong></td>
          <td>${lat} ms</td>
          <td><strong>${gps}</strong></td>
          <td><span class="badge ${name === 'MD5' || name === 'SHA-256' ? 'badge-danger' : 'badge-success'}">${ratio}x slower</span></td>
          <td>${mem}</td>
          <td><code>${formatParams(item.params)}</code></td>
        </tr>
      `;
    });
    container.innerHTML = rows;

    // Populate Exposure milestones if available
    const milestonesTbody = document.getElementById("milestonesTableBody");
    if (milestonesTbody && data.phase4_attack_simulation) {
      const exp = data.phase4_attack_simulation.exposure_projection;
      let mRows = "";
      algos.forEach(name => {
        const item = exp[name];
        mRows += `
          <tr>
            <td><strong>${name}</strong></td>
            <td>${item.pct_at_1_second.toFixed(1)}%</td>
            <td>${item.pct_at_1_hour.toFixed(1)}%</td>
            <td>${item.pct_at_1_day.toFixed(1)}%</td>
            <td>${item.pct_at_1_year.toFixed(1)}%</td>
            <td>${item.max_recoverable_pct.toFixed(1)}%</td>
          </tr>
        `;
      });
      milestonesTbody.innerHTML = mRows;
    }

  } catch (err) {
    console.error("Error loading benchmark results:", err);
  }
}

function formatParams(params) {
  if (!params || Object.keys(params).length === 0) return "Fixed Digest";
  return Object.entries(params)
    .filter(([k]) => k !== "maxmem")
    .map(([k, v]) => `${k}=${v}`)
    .join(", ");
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
