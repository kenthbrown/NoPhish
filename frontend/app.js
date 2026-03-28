const analyzeButton = document.getElementById("analyze-button");
const exampleButton = document.getElementById("example-button");
const refreshAuditButton = document.getElementById("refresh-audit");
const analysisInput = document.getElementById("analysis-text");
const statusMessage = document.getElementById("status-message");
const resultCard = document.getElementById("result-card");
const resultBadge = document.getElementById("result-badge");
const confidenceValue = document.getElementById("confidence-value");
const reasonsList = document.getElementById("reasons-list");
const auditList = document.getElementById("audit-list");
const defaultAnalyzeLabel = analyzeButton.textContent;
const exampleText = "URGENT: Verify your account now at bit.ly/login-secure";

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
  resultCard.classList.remove("hidden");
  resultBadge.textContent = data.result;
  resultBadge.className = `result-badge ${getResultClass(data.result)}`;
  confidenceValue.textContent = data.confidence;

  reasonsList.innerHTML = "";

  const reasons = data.reasons.length
    ? data.reasons
    : ["No phishing indicators were triggered by the current rules."];

  reasons.forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    reasonsList.appendChild(item);
  });
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
  try {
    const response = await fetch("/audit");

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
    await loadAudit();
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

analyzeButton.addEventListener("click", analyzeInput);
exampleButton.addEventListener("click", fillExample);
refreshAuditButton.addEventListener("click", loadAudit);

analysisInput.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    analyzeInput();
  }
});

loadAudit();
