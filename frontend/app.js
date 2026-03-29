const analyzeButton = document.getElementById("analyze-button");
const refreshButton = document.getElementById("refreshBtn");
const analysisInput = document.getElementById("analysis-text");
const statusMessage = document.getElementById("status-message");
const resultCard = document.getElementById("result-card");
const resultContent = document.getElementById("result-content");
const recentChecks = document.getElementById("recentChecks");
const scanDetails = document.getElementById("scanDetails");
const chartBars = document.getElementById("chart-bars");
const statAnalyses = document.getElementById("stat-analyses");
const statDetections = document.getElementById("stat-detections");
const statReports = document.getElementById("stat-reports");
const statBrand = document.getElementById("stat-brand");
const trendHighest = document.getElementById("trend-highest");
const trendAverage = document.getElementById("trend-average");
const trendLatestBrand = document.getElementById("trend-latest-brand");
const trendCommonAttack = document.getElementById("trend-common-attack");
const scenarioButtons = document.querySelectorAll("[data-scenario]");
const filterButtons = document.querySelectorAll("[data-filter]");
const defaultAnalyzeLabel = analyzeButton.textContent;
const scenarios = {
  safe: "https://www.paypal.com",
  suspicious: "https://g00gle.com/login",
  phishing: "URGENT: Verify your account now at bit.ly/login-secure",
};
let latestAnalysis = null;
let latestAuditEntries = [];
let activeFilter = "All";
let autoRefreshId = null;
let selectedScanKey = null;
const EMPTY_DASH = "\u2014";

function getResultClass(result) {
  if (result === "Safe") {
    return "result-safe";
  }

  if (result === "Likely Phishing") {
    return "result-likely-phishing";
  }

  return "result-suspicious";
}

function getRiskCardClass(result) {
  if (result === "Safe") {
    return "risk-safe";
  }

  if (result === "Likely Phishing") {
    return "risk-likely-phishing";
  }

  return "risk-suspicious";
}

function getRiskBarClass(score) {
  if (score >= 60) {
    return "score-danger";
  }

  if (score >= 30) {
    return "score-suspicious";
  }

  return "score-safe";
}

function setStatus(message) {
  statusMessage.textContent = message;
}

function setElementText(element, value) {
  if (element) {
    element.textContent = value;
  }
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatTimestamp(value) {
  return new Date(value).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function formatAuditPreview(value) {
  const normalized = String(value).replace(/\s+/g, " ").trim();
  return normalized.length > 88 ? `${normalized.slice(0, 85)}...` : normalized;
}

function delay(ms) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

function getRecentCheckKey(entry) {
  return `${entry.timestamp || ""}::${entry.input || ""}::${entry.result || ""}`;
}

function dedupeRecentChecks(entries) {
  const seen = new Set();

  return entries.filter((entry) => {
    const key = getRecentCheckKey(entry);

    if (seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  });
}

function getAttackTypeDisplay(tag) {
  const iconMap = {
    "Urgency Language": "⚠️",
    "Credential Harvesting": "🔐",
    "Shortened URL": "🌐",
    "Insecure Link": "🔓",
    "Lookalike Domain": "🕵️",
    "Brand Impersonation": "🏷️",
    "Suspicious Domain Pattern": "🚩",
  };

  return `${iconMap[tag] || "•"} ${tag}`;
}

function getAttackTypeMarkup(tag) {
  const iconMap = {
    "Social Engineering": "&#9888;&#65039;",
    "Credential Harvesting": "&#128274;",
    "Shortened URL": "&#127760;",
    "Insecure Link": "&#128275;",
    "Lookalike Domain": "&#128373;&#65039;",
    "Brand Impersonation": "&#127991;&#65039;",
    "Suspicious Domain Pattern": "&#128681;",
  };

  return `${iconMap[tag] || "&bull;"} ${escapeHtml(tag)}`;
}

function buildAnalystSummary(result, attackTypes, targetBrand) {
  if (result === "Safe") {
    return "Analyst assessment: no meaningful phishing indicators were triggered by the current heuristics.";
  }

  const primaryType = attackTypes[0] || "deceptive messaging";
  const brandText = targetBrand ? ` targeting ${targetBrand}` : "";

  if (result === "Likely Phishing") {
    return `Analyst assessment: this input shows strong signs of ${primaryType.toLowerCase()}${brandText}, indicating a likely phishing attempt.`;
  }

  return `Analyst assessment: this input shows moderate signs of ${primaryType.toLowerCase()}${brandText} and should be treated as suspicious pending further review.`;
}

function renderChart(entries) {
  if (!chartBars) {
    return;
  }

  const counts = {
    Safe: 0,
    Suspicious: 0,
    "Likely Phishing": 0,
  };

  entries.forEach((entry) => {
    if (counts[entry.result] !== undefined) {
      counts[entry.result] += 1;
    }
  });

  const maxCount = Math.max(1, ...Object.values(counts));
  const chartConfig = [
    { label: "Safe", value: counts.Safe, className: "result-safe" },
    { label: "Suspicious", value: counts.Suspicious, className: "result-suspicious" },
    { label: "Likely Phishing", value: counts["Likely Phishing"], className: "result-likely-phishing" },
  ];

  chartBars.innerHTML = chartConfig
    .map(
      (item) => `
        <article class="chart-item">
          <div class="chart-label-row">
            <span>${item.label}</span>
            <strong>${item.value}</strong>
          </div>
          <div class="chart-track">
            <div class="chart-fill ${item.className}" style="width:${(item.value / maxCount) * 100}%"></div>
          </div>
        </article>
      `
    )
    .join("");
}

function renderTrendStats(entries) {
  if (!entries.length) {
    setElementText(trendHighest, EMPTY_DASH);
    setElementText(trendAverage, EMPTY_DASH);
    setElementText(trendLatestBrand, EMPTY_DASH);
    setElementText(trendCommonAttack, EMPTY_DASH);
    return;
  }

  const scores = entries
    .map((entry) => Number(entry.score))
    .filter((value) => Number.isFinite(value));
  const highest = scores.length ? Math.max(...scores) : null;
  const average = scores.length ? Math.round(scores.reduce((sum, value) => sum + value, 0) / scores.length) : null;
  const latestBrand = [...entries]
    .reverse()
    .find((entry) => typeof entry.targetBrand === "string" && entry.targetBrand.trim())?.targetBrand || EMPTY_DASH;
  const attackCounts = {};

  entries.forEach((entry) => {
    (entry.attackTypes || []).forEach((type) => {
      attackCounts[type] = (attackCounts[type] || 0) + 1;
    });
  });

  const mostCommonAttack = Object.entries(attackCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || EMPTY_DASH;

  setElementText(trendHighest, highest === null ? EMPTY_DASH : `${highest}%`);
  setElementText(trendAverage, average === null ? EMPTY_DASH : `${average}%`);
  setElementText(trendLatestBrand, latestBrand);
  setElementText(trendCommonAttack, mostCommonAttack);
}

function applyFilterState() {
  filterButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.filter === activeFilter);
  });
}

function buildDetailsMarkup(entry) {
  const confidence = Number.isFinite(Number(entry.score)) ? Number(entry.score) : 0;
  const attackTypes = Array.isArray(entry.attackTypes) ? entry.attackTypes : [];
  const reasons = Array.isArray(entry.reasons) && entry.reasons.length
    ? entry.reasons
    : ["No detailed reasons available for this scan."];
  const breakdown = Array.isArray(entry.breakdown) && entry.breakdown.length
    ? entry.breakdown
    : ["No confidence breakdown available for this scan."];
  const explanation = typeof entry.explanation === "string" && entry.explanation.trim()
    ? entry.explanation
    : "No explanation was recorded for this scan.";
  const analystSummary = typeof entry.analystSummary === "string" && entry.analystSummary.trim()
    ? entry.analystSummary
    : buildAnalystSummary(entry.result, attackTypes, entry.targetBrand || "");

  return `
    <div class="section-header">
      <h2>Scan Details</h2>
      <span class="result-badge ${getResultClass(entry.result)}">${escapeHtml(entry.result)}</span>
    </div>
    <div class="result-meta">
      <p class="confidence-line"><strong>Risk Score:</strong> <span class="confidence-value">${confidence}%</span></p>
      <p class="confidence-line"><strong>Timestamp:</strong> ${escapeHtml(formatTimestamp(entry.timestamp))}</p>
    </div>
    <div class="score-bar-shell">
      <div class="score-bar-track">
        <div class="score-bar-fill ${getRiskBarClass(confidence)}" data-score-bar data-target-width="${confidence}%"></div>
      </div>
    </div>
    <div>
      <h3>Analyzed Input</h3>
      <p class="detail-input">${escapeHtml(entry.input || "")}</p>
    </div>
    ${entry.targetBrand ? `
      <div>
        <h3>Target Brand</h3>
        <p class="target-brand">${escapeHtml(entry.targetBrand)}</p>
      </div>
    ` : ""}
    ${attackTypes.length ? `
      <div>
        <h3>Attack Types</h3>
        <ul class="tag-list">
          ${attackTypes.map((tag) => `<li>${getAttackTypeMarkup(tag)}</li>`).join("")}
        </ul>
      </div>
    ` : ""}
    <div>
      <h3>Reasons</h3>
      <ul class="reasons-list">
        ${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}
      </ul>
    </div>
    <div>
      <h3>Confidence Breakdown</h3>
      <ul class="reasons-list">
        ${breakdown.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
      </ul>
    </div>
    <div class="danger-box">
      <h3>Why this is dangerous:</h3>
      <p class="danger-explanation">${escapeHtml(explanation)}</p>
    </div>
    <div class="summary-box">
      <h3>Analyst Summary</h3>
      <p class="danger-explanation">${escapeHtml(analystSummary)}</p>
    </div>
  `;
}

function renderScanDetails(entry) {
  if (!scanDetails) {
    return;
  }

  if (!entry) {
    scanDetails.className = "scan-details-empty";
    scanDetails.textContent = "Select a recent check to inspect details.";
    return;
  }

  scanDetails.className = "scan-details-content";
  scanDetails.innerHTML = buildDetailsMarkup(entry);
  animateScoreBars(scanDetails);
}

function renderLoadingState() {
  if (!resultCard || !resultContent) {
    return;
  }

  resultCard.classList.remove("hidden", "risk-safe", "risk-suspicious", "risk-likely-phishing", "result-enter");
  resultCard.classList.add("is-loading");
  resultContent.innerHTML = `
    <div class="skeleton-header">
      <div class="skeleton skeleton-title"></div>
      <div class="skeleton skeleton-pill"></div>
    </div>
    <div class="skeleton skeleton-score"></div>
    <div class="skeleton skeleton-progress"></div>
    <div class="skeleton-tags">
      <span class="skeleton skeleton-tag"></span>
      <span class="skeleton skeleton-tag"></span>
      <span class="skeleton skeleton-tag"></span>
    </div>
    <div class="skeleton-list">
      <div class="skeleton skeleton-line"></div>
      <div class="skeleton skeleton-line"></div>
      <div class="skeleton skeleton-line skeleton-line-short"></div>
    </div>
    <div class="skeleton-block">
      <div class="skeleton skeleton-subtitle"></div>
      <div class="skeleton skeleton-line"></div>
      <div class="skeleton skeleton-line skeleton-line-short"></div>
    </div>
  `;
}

function animateScoreBars(scope = document) {
  const bars = scope.querySelectorAll("[data-score-bar]");

  bars.forEach((bar) => {
    bar.style.width = "0%";
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => {
        bar.style.width = bar.dataset.targetWidth || "0%";
      });
    });
  });
}

function renderResult(data) {
  if (!resultCard || !resultContent) {
    return;
  }

  const confidence = typeof data.confidence === "number" ? data.confidence : 0;
  const reasons = Array.isArray(data.reasons) && data.reasons.length
    ? data.reasons
    : ["No phishing indicators were triggered by the current rules."];
  const breakdownItems = Array.isArray(data.breakdown) && data.breakdown.length
    ? data.breakdown
    : [];
  const explanation = typeof data.explanation === "string" && data.explanation.trim()
    ? data.explanation
    : "No additional explanation is available for this result.";
  const targetBrand = typeof data.targetBrand === "string" && data.targetBrand.trim()
    ? data.targetBrand
    : "";
  const tags = Array.isArray(data.attackTypes) && data.attackTypes.length
    ? data.attackTypes
    : Array.isArray(data.tags) && data.tags.length
      ? data.tags
      : [];
  const analystSummary = buildAnalystSummary(data.result, tags, targetBrand);

  latestAnalysis = {
    text: analysisInput.value.trim(),
    result: data.result,
    confidence,
    attackTypes: tags,
    reasons,
    breakdown: breakdownItems,
    targetBrand,
    explanation,
    analystSummary,
    timestamp: new Date().toISOString(),
  };

  resultCard.classList.remove("hidden");
  resultCard.classList.remove("risk-safe", "risk-suspicious", "risk-likely-phishing", "is-loading", "result-enter");
  resultCard.classList.add(getRiskCardClass(data.result));
  resultContent.innerHTML = `
    <div class="section-header">
      <h2>Analysis Result</h2>
      <span class="result-badge ${getResultClass(data.result)}">${escapeHtml(data.result)}</span>
    </div>

    <div class="result-meta">
      <p class="confidence-line"><strong>Risk Score:</strong> <span class="confidence-value">${confidence}%</span></p>
    </div>

    <div class="score-bar-shell">
      <div class="score-bar-track">
        <div class="score-bar-fill ${getRiskBarClass(confidence)}" data-score-bar data-target-width="${confidence}%"></div>
      </div>
    </div>

    ${targetBrand ? `
      <div>
        <h3>Target Brand</h3>
        <p class="target-brand">${escapeHtml(targetBrand)}</p>
      </div>
    ` : ""}

    ${tags.length ? `
      <div>
        <h3>Attack Types</h3>
        <ul class="tag-list">
          ${tags.map((tag) => `<li>${getAttackTypeMarkup(tag)}</li>`).join("")}
        </ul>
      </div>
    ` : ""}

    <div>
      <h3>Reasons</h3>
      <ul class="reasons-list">
        ${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}
      </ul>
    </div>

    ${breakdownItems.length ? `
      <div>
        <h3>Confidence Breakdown</h3>
        <ul class="reasons-list">
          ${breakdownItems.map((entry) => `<li>${escapeHtml(entry)}</li>`).join("")}
        </ul>
      </div>
    ` : ""}

    <div class="danger-box">
      <h3>Why this is dangerous:</h3>
      <p class="danger-explanation">${escapeHtml(explanation)}</p>
    </div>

    <div class="summary-box">
      <h3>Analyst Summary</h3>
      <p class="danger-explanation">${escapeHtml(analystSummary)}</p>
    </div>

    <div class="result-actions">
      <button id="report-button" class="secondary-button" type="button">Report as Phishing</button>
      <button id="export-button" class="secondary-button" type="button">Export Report</button>
      <p id="report-status" class="status-message" aria-live="polite"></p>
    </div>
  `;

  const reportButton = document.getElementById("report-button");
  if (reportButton) {
    reportButton.disabled = false;
    reportButton.addEventListener("click", reportLatestAnalysis);
  }

  const exportButton = document.getElementById("export-button");
  if (exportButton) {
    exportButton.addEventListener("click", exportLatestAnalysis);
  }

  window.requestAnimationFrame(() => {
    resultCard.classList.add("result-enter");
    animateScoreBars(resultContent);
  });
}

function renderAudit(entries) {
  if (!recentChecks) {
    return;
  }

  recentChecks.innerHTML = "";
  const filteredEntries = activeFilter === "All"
    ? entries
    : entries.filter((entry) => entry.result === activeFilter);

  if (!filteredEntries.length) {
    recentChecks.classList.remove("event-feed");
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = activeFilter === "All" ? "No checks recorded yet." : `No ${activeFilter.toLowerCase()} checks found.`;
    recentChecks.appendChild(empty);
    return;
  }

  recentChecks.classList.add("event-feed");

  filteredEntries
    .slice()
    .reverse()
    .slice(0, 5)
    .forEach((entry) => {
      const item = document.createElement("article");
      item.className = "audit-item";
      item.tabIndex = 0;
      item.setAttribute("role", "button");
      const entryKey = getRecentCheckKey(entry);
      item.classList.toggle("active", entryKey === selectedScanKey);

      const meta = document.createElement("div");
      meta.className = "audit-meta";

      const timestamp = document.createElement("span");
      timestamp.textContent = formatTimestamp(entry.timestamp);

      const result = document.createElement("span");
      result.textContent = entry.result;
      result.className = `result-badge ${getResultClass(entry.result)}`;

      meta.append(timestamp, result);

      const input = document.createElement("p");
      input.className = "audit-input";
      input.textContent = formatAuditPreview(entry.input);

      item.append(meta, input);
      item.addEventListener("click", () => {
        selectedScanKey = entryKey;
        renderAudit(latestAuditEntries);
        renderScanDetails(entry);
      });
      item.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          selectedScanKey = entryKey;
          renderAudit(latestAuditEntries);
          renderScanDetails(entry);
        }
      });
      recentChecks.appendChild(item);
    });
}

async function loadRecentChecks() {
  if (refreshButton) {
    refreshButton.disabled = true;
  }

  try {
    const response = await fetch("/audit", {
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error("Unable to load audit log.");
    }

    latestAuditEntries = dedupeRecentChecks(await response.json()).slice(-5);
    renderAudit(latestAuditEntries);
    renderChart(latestAuditEntries);
    renderTrendStats(latestAuditEntries);

    if (selectedScanKey) {
      const selectedEntry = latestAuditEntries.find((entry) => getRecentCheckKey(entry) === selectedScanKey);
      renderScanDetails(selectedEntry || null);

      if (!selectedEntry) {
        selectedScanKey = null;
      }
    } else {
      renderScanDetails(null);
    }
  } catch (error) {
    if (!recentChecks) {
      return;
    }

    recentChecks.innerHTML = "";

    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = error.message;
    recentChecks.appendChild(empty);
    renderTrendStats([]);
  } finally {
    if (refreshButton) {
      refreshButton.disabled = false;
    }
  }
}

async function loadStats() {
  try {
    const response = await fetch("/stats", {
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error("Unable to load stats.");
    }

    const stats = await response.json();
    setElementText(statAnalyses, stats.totalAnalyses);
    setElementText(statDetections, stats.totalDetections);
    setElementText(statReports, stats.totalReports);
    setElementText(statBrand, stats.mostImpersonatedBrand || EMPTY_DASH);
  } catch (_error) {
    setElementText(statAnalyses, "-");
    setElementText(statDetections, "-");
    setElementText(statReports, "-");
    setElementText(statBrand, EMPTY_DASH);
  }
}

function exportLatestAnalysis() {
  if (!latestAnalysis) {
    setStatus("Run an analysis before exporting a report.");
    return;
  }

  const exportPayload = {
    analyzedInput: latestAnalysis.text,
    result: latestAnalysis.result,
    confidence: latestAnalysis.confidence,
    attackTypes: latestAnalysis.attackTypes,
    reasons: latestAnalysis.reasons,
    breakdown: latestAnalysis.breakdown,
    targetBrand: latestAnalysis.targetBrand,
    explanation: latestAnalysis.explanation,
    analystSummary: latestAnalysis.analystSummary,
    timestamp: latestAnalysis.timestamp,
  };

  const blob = new Blob([JSON.stringify(exportPayload, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `nophish-report-${Date.now()}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function analyzeInput() {
  const text = analysisInput.value.trim();

  if (!text) {
    setStatus("Please enter a URL or message");
    analysisInput.focus();
    return;
  }

  analyzeButton.disabled = true;
  analyzeButton.textContent = "Analyzing...";
  setStatus("Analyzing...");
  renderLoadingState();

  try {
    const [response] = await Promise.all([
      fetch("/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ text }),
      }),
      delay(1100),
    ]);

    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error || "Analysis failed.");
    }

    renderResult(payload);
    setStatus("Analysis complete.");
    await Promise.all([loadRecentChecks(), loadStats()]);
  } catch (error) {
    setStatus(error.message);
  } finally {
    analyzeButton.disabled = false;
    analyzeButton.textContent = defaultAnalyzeLabel;
  }
}

function fillScenario(name) {
  analysisInput.value = scenarios[name] || scenarios.phishing;
  analysisInput.focus();
  setStatus("Demo scenario loaded.");
}

async function reportLatestAnalysis() {
  const reportButton = document.getElementById("report-button");
  const reportStatus = document.getElementById("report-status");

  if (!latestAnalysis) {
    setElementText(reportStatus, "Run an analysis before reporting.");
    return;
  }

  if (reportButton) {
    reportButton.disabled = true;
  }
  setElementText(reportStatus, "Submitting report...");

  try {
    const response = await fetch("/report", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(latestAnalysis),
    });

    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error || "Unable to submit report.");
    }

    setElementText(reportStatus, payload.message);
    await loadStats();
  } catch (error) {
    setElementText(reportStatus, error.message);
    if (reportButton) {
      reportButton.disabled = false;
    }
  }
}

analyzeButton.addEventListener("click", analyzeInput);
if (refreshButton) {
  refreshButton.addEventListener("click", loadRecentChecks);
}
scenarioButtons.forEach((button) => {
  button.addEventListener("click", () => fillScenario(button.dataset.scenario));
});
filterButtons.forEach((button) => {
  button.addEventListener("click", () => {
    activeFilter = button.dataset.filter || "All";
    applyFilterState();
    renderAudit(latestAuditEntries);
  });
});

analysisInput.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    analyzeInput();
  }
});

loadRecentChecks();
loadStats();
applyFilterState();

autoRefreshId = window.setInterval(() => {
  loadRecentChecks();
}, 5000);
