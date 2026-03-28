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
const trustedDomains = [
  "paypal.com",
  "amazon.com",
  "microsoft.com",
  "bankofamerica.com",
  "apple.com",
  "google.com",
];

app.use(express.json());
app.use(express.static(path.join(__dirname, "../frontend")));

function getDomainLikeSegments(text) {
  const matches = text.match(/\b(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/gi);
  return matches || [];
}

function normalizeHost(segment) {
  return segment
    .replace(/^https?:\/\//i, "")
    .replace(/^www\./i, "")
    .split(/[/?#:]/)[0]
    .toLowerCase();
}

function getPrimaryDomain(host) {
  const parts = host.split(".").filter(Boolean);

  if (parts.length < 2) {
    return host;
  }

  return parts.slice(-2).join(".");
}

function getDomainsFromText(text) {
  return getDomainLikeSegments(text).map((segment) => getPrimaryDomain(normalizeHost(segment)));
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

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function buildLookalikeRegex(domain) {
  let pattern = "";

  for (let index = 0; index < domain.length; index += 1) {
    const char = domain[index];

    if (char === "l" || char === "i") {
      pattern += "[li1I]";
    } else if (char === "o") {
      pattern += "[o0]";
    } else if (char === "m") {
      pattern += "(?:m|rn)";
    } else {
      pattern += escapeRegExp(char);
    }
  }

  return new RegExp(`^${pattern}$`, "i");
}

function detectLookalikeDomains(text) {
  const matchedReasons = [];
  const seenReasons = new Set();
  const candidateDomains = getDomainsFromText(text);

  candidateDomains.forEach((candidate) => {
    trustedDomains.forEach((trustedDomain) => {
      if (candidate === trustedDomain) {
        return;
      }

      const trustedRegex = buildLookalikeRegex(trustedDomain);

      if (trustedRegex.test(candidate)) {
        const reason = `Possible lookalike domain impersonating ${trustedDomain}`;

        if (!seenReasons.has(reason)) {
          seenReasons.add(reason);
          matchedReasons.push(reason);
        }
      }
    });
  });

  return matchedReasons;
}

function analyzeText(text) {
  const reasons = [];
  const normalizedText = text.toLowerCase();
  let riskScore = 0;

  function addReason(reason, weight = 1) {
    reasons.push(reason);
    riskScore += weight;
  }

  suspiciousKeywords.forEach((keyword) => {
    if (normalizedText.includes(keyword)) {
      addReason(`Contains suspicious keyword: "${keyword}"`);
    }
  });

  urlShorteners.forEach((shortener) => {
    if (normalizedText.includes(shortener)) {
      addReason(`Uses URL shortener: "${shortener}"`);
    }
  });

  if (hasMultipleDotsInDomain(text)) {
    addReason("URL contains multiple dots in the domain");
  }

  if (hasAtSymbolInUrl(text)) {
    addReason('URL contains "@" which can obscure the true destination');
  }

  if (hasLongRandomLookingString(text)) {
    addReason("Contains a long random-looking string");
  }

  detectLookalikeDomains(text).forEach((reason) => {
    addReason(reason, 2);
  });

  let result = "Safe";
  let confidence = "Low";

  if (riskScore >= 3) {
    result = "Likely Phishing";
    confidence = "High";
  } else if (riskScore >= 1) {
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
