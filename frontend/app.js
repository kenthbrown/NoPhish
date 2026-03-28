const analyzeButton = document.getElementById("analyze-button");
const exampleButton = document.getElementById("example-button");
const refreshAuditButton = document.getElementById("refresh-audit");
const analysisInput = document.getElementById("analysis-text");
const statusMessage = document.getElementById("status-message");
const resultCard = document.getElementById("result-card");
const resultBadge = document.getElementById("result-badge");
const confidenceValue = document.getElementById("confidence-value");
const reasonsList = document.getElementById("reasons-list");
const breakdownList = document.getElementById("breakdown-list");
const dangerExplanation = document.getElementById("danger-explanation");
const reportButton = document.getElementById("report-button");
const reportStatus = document.getElementById("report-status");
const auditList = document.getElementById("audit-list");
const statAnalyses = document.getElementById("stat-analyses");
const statDetections = document.getElementById("stat-detections");
const statReports = document.getElementById("stat-reports");
const defaultAnalyzeLabel = analyzeButton.textContent;
const exampleText = "URGENT: Verify your account now at bit.ly/login-secure";
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

function setStatus(message) {
  statusMessage.textContent = message;
}

function formatTimestamp(value) {
  return new Date(value).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function renderResult(data) {
  latestAnalysis = {
    text: analysisInput.value.trim(),
    result: data.result,
    score: data.confidence,
  };

  resultCard.classList.remove("hidden");
  resultBadge.textContent = data.result;
  resultBadge.className = `result-badge ${getResultClass(data.result)}`;
  const confidence = typeof data.confidence === "number" ? data.confidence : 0;
  confidenceValue.textContent = `${confidence}%`;
  reportStatus.textContent = "";
  reportButton.disabled = false;

  reasonsList.innerHTML = "";
  breakdownList.innerHTML = "";

  const reasons = data.reasons.length
    ? data.reasons
    : ["No phishing indicators were triggered by the current rules."];

  reasons.forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    reasonsList.appendChild(item);
  });

  const breakdownItems = data.breakdown.length
    ? data.breakdown
    : ["No risk points were added."];

  breakdownItems.forEach((entry) => {
    const item = document.createElement("li");
    item.textContent = entry;
    breakdownList.appendChild(item);
  });

  dangerExplanation.textContent = data.explanation;
}

function renderAudit(entries) {
  auditList.innerHTML = "";

  if (!entries.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No checks recorded yet.";
    auditList.appendChild(empty);
    return;
  }

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
      input.textContent = entry.input;

      item.append(meta, input);
      auditList.appendChild(item);
    });
}

async function loadAudit() {
  refreshAuditButton.disabled = true;

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
    auditList.innerHTML = "";

    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = error.message;
    auditList.appendChild(empty);
  } finally {
    refreshAuditButton.disabled = false;
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
    statAnalyses.textContent = stats.totalAnalyses;
    statDetections.textContent = stats.phishingDetections;
    statReports.textContent = stats.totalReports;
  } catch (_error) {
    statAnalyses.textContent = "-";
    statDetections.textContent = "-";
    statReports.textContent = "-";
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
    await Promise.all([loadAudit(), loadStats()]);
  } catch (error) {
    setStatus(error.message);
  } finally {
    analyzeButton.disabled = false;
    analyzeButton.textContent = defaultAnalyzeLabel;
  }
}

function fillExample() {
  analysisInput.value = exampleText;
  analysisInput.focus();
  setStatus("Example loaded. Click Analyze to test it.");
}

async function reportLatestAnalysis() {
  if (!latestAnalysis) {
    reportStatus.textContent = "Run an analysis before reporting.";
    return;
  }

  reportButton.disabled = true;
  reportStatus.textContent = "Submitting report...";

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

    reportStatus.textContent = payload.message;
    await loadStats();
  } catch (error) {
    reportStatus.textContent = error.message;
    reportButton.disabled = false;
  }
}

analyzeButton.addEventListener("click", analyzeInput);
exampleButton.addEventListener("click", fillExample);
refreshAuditButton.addEventListener("click", loadAudit);
reportButton.addEventListener("click", reportLatestAnalysis);

analysisInput.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    analyzeInput();
  }
});

loadAudit();
loadStats();
