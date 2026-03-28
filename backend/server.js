const express = require("express");
const path = require("path");

const app = express();
const PORT = 3000;

const auditLog = [];

const suspiciousKeywords = [
  "urgent",
  "verify",
  "login",
  "password",
  "account",
  "bank",
  "click here",
];

const urlShorteners = ["bit.ly", "tinyurl", "goo.gl"];

app.use(express.json());
app.use(express.static(path.join(__dirname, "../frontend")));

function getDomainLikeSegments(text) {
  const matches = text.match(/\b(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/gi);
  return matches || [];
}

function hasMultipleDotsInDomain(text) {
  const segments = getDomainLikeSegments(text);

  return segments.some((segment) => {
    const normalized = segment
      .replace(/^https?:\/\//i, "")
      .replace(/^www\./i, "")
      .split(/[/?#:]/)[0];

    const dotCount = (normalized.match(/\./g) || []).length;
    return dotCount >= 2;
  });
}

function hasAtSymbolInUrl(text) {
  return /https?:\/\/\S*@\S+/i.test(text) || /\bwww\.\S*@\S+/i.test(text);
}

function hasLongRandomLookingString(text) {
  return /\b[a-z0-9]{18,}\b/i.test(text);
}

function analyzeText(text) {
  const reasons = [];
  const normalizedText = text.toLowerCase();

  suspiciousKeywords.forEach((keyword) => {
    if (normalizedText.includes(keyword)) {
      reasons.push(`Contains suspicious keyword: "${keyword}"`);
    }
  });

  urlShorteners.forEach((shortener) => {
    if (normalizedText.includes(shortener)) {
      reasons.push(`Uses URL shortener: "${shortener}"`);
    }
  });

  if (hasMultipleDotsInDomain(text)) {
    reasons.push("URL contains multiple dots in the domain");
  }

  if (hasAtSymbolInUrl(text)) {
    reasons.push('URL contains "@" which can obscure the true destination');
  }

  if (hasLongRandomLookingString(text)) {
    reasons.push("Contains a long random-looking string");
  }

  let result = "Safe";
  let confidence = "Low";

  if (reasons.length >= 3) {
    result = "Likely Phishing";
    confidence = "High";
  } else if (reasons.length >= 1) {
    result = "Suspicious";
    confidence = "Medium";
  }

  return {
    result,
    reasons,
    confidence,
  };
}

app.post("/analyze", (req, res) => {
  const { text } = req.body || {};

  if (typeof text !== "string" || !text.trim()) {
    return res.status(400).json({
      error: 'The request body must include a non-empty "text" field.',
    });
  }

  const analysis = analyzeText(text);

  auditLog.push({
    timestamp: new Date().toISOString(),
    input: text,
    result: analysis.result,
  });

  return res.json(analysis);
});

app.get("/audit", (_req, res) => {
  res.json(auditLog);
});

app.listen(PORT, () => {
  console.log("NoPhish server running on port 3000");
});
