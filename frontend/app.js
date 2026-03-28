const analyzeButton = document.getElementById("analyze-button");
const refreshButton = document.getElementById("refreshBtn");
const analysisInput = document.getElementById("analysis-text");
const statusMessage = document.getElementById("status-message");
const resultCard = document.getElementById("result-card");
const resultContent = document.getElementById("result-content");
const recentChecks = document.getElementById("recentChecks");
const statAnalyses = document.getElementById("stat-analyses");
const statDetections = document.getElementById("stat-detections");
const statReports = document.getElementById("stat-reports");
const statBrand = document.getElementById("stat-brand");
const scenarioButtons = document.querySelectorAll("[data-scenario]");
const defaultAnalyzeLabel = analyzeButton.textContent;
const scenarios = {
  safe: "https://www.paypal.com",
  suspicious: "https://g00gle.com/login",
  phishing: "URGENT: Verify your account now at bit.ly/login-secure",
};
let latestAnalysis = null;

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

  latestAnalysis = {
    text: analysisInput.value.trim(),
    result: data.result,
    score: confidence,
  };

  resultCard.classList.remove("hidden");
  resultCard.classList.remove("risk-safe", "risk-suspicious", "risk-likely-phishing");
  resultCard.classList.add(getRiskCardClass(data.result));
  resultContent.innerHTML = `
    <div class="section-header">
      <h2>Analysis Result</h2>
      <span class="result-badge ${getResultClass(data.result)}">${escapeHtml(data.result)}</span>
    </div>

    <div class="result-meta">
      <p class="confidence-line"><strong>Confidence:</strong> <span class="confidence-value">${confidence}%</span></p>
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
          ${tags.map((tag) => `<li>${escapeHtml(tag)}</li>`).join("")}
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

    <div class="result-actions">
      <button id="report-button" class="secondary-button" type="button">Report as Phishing</button>
      <p id="report-status" class="status-message" aria-live="polite"></p>
    </div>
  `;

  const reportButton = document.getElementById("report-button");
  if (reportButton) {
    reportButton.disabled = false;
    reportButton.addEventListener("click", reportLatestAnalysis);
  }
}

function renderAudit(entries) {
  if (!recentChecks) {
    return;
  }

  recentChecks.innerHTML = "";

  if (!entries.length) {
    recentChecks.classList.remove("event-feed");
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No checks recorded yet.";
    recentChecks.appendChild(empty);
    return;
  }

  recentChecks.classList.add("event-feed");

  entries
    .slice()
    .reverse()
    .slice(0, 5)
    .forEach((entry) => {
      const item = document.createElement("article");
      item.className = "audit-item";

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

    const entries = await response.json();
    renderAudit(entries);
  } catch (error) {
    if (!recentChecks) {
      return;
    }

    recentChecks.innerHTML = "";

    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = error.message;
    recentChecks.appendChild(empty);
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
    setElementText(statBrand, stats.mostImpersonatedBrand);
  } catch (_error) {
    setElementText(statAnalyses, "-");
    setElementText(statDetections, "-");
    setElementText(statReports, "-");
    setElementText(statBrand, "-");
  }
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

  try {
    const response = await fetch("/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ text }),
    });

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

analysisInput.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    analyzeInput();
  }
});

loadRecentChecks();
loadStats();
