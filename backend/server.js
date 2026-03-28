const express = require("express");
const path = require("path");

const app = express();
const PORT = 3000;

const auditLog = [];
const reportedItems = [];

const keywordSignals = [
  { term: "verify", points: 5 },
  { term: "login", points: 5 },
  { term: "password", points: 5 },
  { term: "account", points: 5 },
  { term: "bank", points: 5 },
  { term: "click here", points: 5 },
];

const urgencySignals = ["urgent", "immediately", "asap", "action required", "suspended"];
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

function getUrlCandidates(text) {
  const matches = text.match(/\b(?:https?:\/\/|www\.)[^\s<>"']+/gi);
  return matches || [];
}

function getDomainLikeSegments(text) {
  const matches = text.match(/\b(?:https?:\/\/)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+[^\s<>"']*/gi);
  return matches || [];
}

function normalizeHost(host) {
  return host
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/\.+$/, "");
}

function getPrimaryDomain(host) {
  const parts = host.split(".").filter(Boolean);
  if (parts.length < 2) {
    return host;
  }

  return parts.slice(-2).join(".");
}

function getSubdomainCount(host) {
  const parts = host.split(".").filter(Boolean);
  return Math.max(parts.length - 2, 0);
}

function safeParseUrl(candidate) {
  try {
    const withScheme = /^[a-z]+:\/\//i.test(candidate) ? candidate : `https://${candidate}`;
    const parsed = new URL(withScheme);

    return {
      raw: candidate,
      protocol: parsed.protocol.toLowerCase(),
      host: normalizeHost(parsed.hostname),
      pathname: parsed.pathname,
      href: parsed.href,
    };
  } catch (_error) {
    return null;
  }
}

function extractInspectableUrls(text) {
  const candidates = [...new Set([...getUrlCandidates(text), ...getDomainLikeSegments(text)])];

  return candidates
    .map((candidate) => safeParseUrl(candidate))
    .filter((value) => value && value.host.includes("."));
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

function getBrandToken(domain) {
  return domain.split(".")[0];
}

function levenshteinDistance(left, right) {
  const matrix = Array.from({ length: left.length + 1 }, () => Array(right.length + 1).fill(0));

  for (let row = 0; row <= left.length; row += 1) {
    matrix[row][0] = row;
  }

  for (let col = 0; col <= right.length; col += 1) {
    matrix[0][col] = col;
  }

  for (let row = 1; row <= left.length; row += 1) {
    for (let col = 1; col <= right.length; col += 1) {
      const cost = left[row - 1] === right[col - 1] ? 0 : 1;
      matrix[row][col] = Math.min(
        matrix[row - 1][col] + 1,
        matrix[row][col - 1] + 1,
        matrix[row - 1][col - 1] + cost
      );
    }
  }

  return matrix[left.length][right.length];
}

function normalizeSimilarityToken(value) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function getSimilarityScore(left, right) {
  const normalizedLeft = normalizeSimilarityToken(left);
  const normalizedRight = normalizeSimilarityToken(right);

  if (!normalizedLeft || !normalizedRight) {
    return 0;
  }

  const distance = levenshteinDistance(normalizedLeft, normalizedRight);
  return 1 - distance / Math.max(normalizedLeft.length, normalizedRight.length);
}

function findClosestTrustedBrand(domain) {
  const token = getBrandToken(domain);
  let bestMatch = null;

  trustedDomains.forEach((trustedDomain) => {
    if (domain === trustedDomain) {
      return;
    }

    const trustedToken = getBrandToken(trustedDomain);
    const similarity = getSimilarityScore(token, trustedToken);

    if (!bestMatch || similarity > bestMatch.similarity) {
      bestMatch = {
        domain: trustedDomain,
        token: trustedToken,
        similarity,
      };
    }
  });

  return bestMatch;
}

function detectDomainSignals(urls) {
  const signals = [];
  const seen = new Set();

  function addSignal(key, reason, breakdown, points, tag, brand) {
    if (seen.has(key)) {
      return;
    }

    seen.add(key);
    signals.push({ key, reason, breakdown, points, tag, brand: brand || null });
  }

  urls.forEach((url) => {
    const primaryDomain = getPrimaryDomain(url.host);
    const subdomainCount = getSubdomainCount(url.host);

    if (url.protocol === "http:") {
      addSignal(
        `http:${url.host}`,
        "URL uses insecure HTTP instead of HTTPS",
        "Insecure HTTP link detected",
        15,
        "Insecure Link"
      );
    }

    if (subdomainCount >= 2) {
      addSignal(
        `subdomains:${url.host}`,
        "URL uses excessive subdomains",
        "Excessive subdomains detected",
        20,
        "Suspicious Domain Pattern"
      );
    }

    if (urlShorteners.includes(primaryDomain)) {
      addSignal(
        `shortener:${primaryDomain}`,
        `Uses URL shortener: "${primaryDomain}"`,
        "Shortened URL detected",
        25,
        "Shortened URL"
      );
    }

    const closestBrand = findClosestTrustedBrand(primaryDomain);
    if (!closestBrand) {
      return;
    }

    const lookalikeRegex = buildLookalikeRegex(closestBrand.domain);
    if (lookalikeRegex.test(primaryDomain) || closestBrand.similarity >= 0.72) {
      addSignal(
        `lookalike:${primaryDomain}:${closestBrand.domain}`,
        `Domain closely resembles trusted brand ${closestBrand.domain}`,
        "Lookalike domain detected",
        40,
        "Lookalike Domain",
        closestBrand.domain
      );
      return;
    }

    if (primaryDomain.includes(closestBrand.token) && closestBrand.similarity >= 0.45) {
      addSignal(
        `brand:${primaryDomain}:${closestBrand.domain}`,
        `Possible brand impersonation targeting ${closestBrand.domain}`,
        "Trusted brand impersonation detected",
        40,
        "Brand Impersonation",
        closestBrand.domain
      );
    }
  });

  return signals;
}

function buildDangerExplanation(result, domainSignals, keywordMatches, hasUrgency, targetBrand) {
  if (result === "Safe") {
    return "This content did not trigger any major phishing indicators in the current heuristic checks.";
  }

  const mainTechnique =
    domainSignals.find((signal) => signal.tag === "Lookalike Domain")?.tag ||
    domainSignals.find((signal) => signal.tag === "Brand Impersonation")?.tag ||
    domainSignals.find((signal) => signal.tag === "Shortened URL")?.tag ||
    (hasUrgency ? "Social Engineering" : null) ||
    (keywordMatches.length ? "Credential Harvesting" : null);

  if (targetBrand && mainTechnique === "Lookalike Domain") {
    return `This input appears to impersonate ${targetBrand} using a lookalike domain and credential-harvesting language.`;
  }

  if (targetBrand && mainTechnique === "Brand Impersonation") {
    return `This input appears to target ${targetBrand} using brand impersonation to make the request look legitimate.`;
  }

  if (targetBrand && keywordMatches.length) {
    return `This input appears to target ${targetBrand} and uses credential-harvesting language that could be used to steal account details.`;
  }

  if (mainTechnique === "Shortened URL") {
    return "This input uses a shortened URL to obscure the destination and could redirect users to a credential theft or malware page.";
  }

  if (hasUrgency && keywordMatches.length) {
    return "This input uses urgency-based social engineering and account-related language to pressure users into revealing sensitive information.";
  }

  return "This input shows phishing-style warning signs that could pressure a user into clicking a deceptive link or sharing sensitive information.";
}

function analyzeText(text) {
  const normalizedText = text.toLowerCase();
  const reasons = [];
  const breakdown = [];
  const tags = [];
  const impersonatedBrands = [];
  const urls = extractInspectableUrls(text);
  const keywordMatches = [];
  const seenSignals = new Set();
  let score = 0;

  function addTag(tag) {
    if (tag && !tags.includes(tag)) {
      tags.push(tag);
    }
  }

  function addBrand(brand) {
    if (brand && !impersonatedBrands.includes(brand)) {
      impersonatedBrands.push(brand);
    }
  }

  function addSignal(key, reason, detail, points, tag, brand) {
    if (seenSignals.has(key)) {
      return;
    }

    seenSignals.add(key);
    reasons.push(reason);
    breakdown.push(`${detail} (+${points})`);
    score += points;
    addTag(tag);
    addBrand(brand);
  }

  const hasUrgency = urgencySignals.some((term) => normalizedText.includes(term));
  if (hasUrgency) {
    addSignal("urgency", "Urgency language detected", "Social engineering language detected", 20, "Social Engineering");
  }

  keywordSignals.forEach((signal) => {
    if (normalizedText.includes(signal.term)) {
      keywordMatches.push(signal.term);
      addSignal(
        `keyword:${signal.term}`,
        `Contains suspicious keyword: "${signal.term}"`,
        `Suspicious keyword detected: ${signal.term}`,
        signal.points,
        ["verify", "login", "password", "account"].includes(signal.term) ? "Credential Harvesting" : null
      );
    }
  });

  const domainSignals = detectDomainSignals(urls);
  domainSignals.forEach((signal) => {
    addSignal(signal.key, signal.reason, signal.breakdown, signal.points, signal.tag, signal.brand);
  });

  if (hasAtSymbolInUrl(text)) {
    addSignal(
      "obscured-destination",
      'URL contains "@" which can obscure the true destination',
      'Obscured destination pattern detected',
      15,
      "Suspicious Domain Pattern"
    );
  }

  if (hasLongRandomLookingString(text)) {
    addSignal(
        "random-string",
        "Contains a long random-looking string",
        "Long random-looking string detected",
        12,
        "Suspicious Domain Pattern"
      );
    }

  score = Math.min(score, 100);

  let result = "Safe";
  if (score >= 60) {
    result = "Likely Phishing";
  } else if (score >= 20) {
    result = "Suspicious";
  }

  const targetBrand = impersonatedBrands[0] || null;
  const explanation = buildDangerExplanation(
    result,
    domainSignals,
    keywordMatches,
    hasUrgency,
    targetBrand
  );

  return {
    result,
    confidence: score,
    reasons,
    score,
    breakdown,
    attackTypes: tags,
    tags,
    impersonatedBrands,
    targetBrand,
    explanation,
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
    score: analysis.confidence,
    tags: analysis.tags,
    impersonatedBrands: analysis.impersonatedBrands,
    targetBrand: analysis.targetBrand,
  });

  return res.json(analysis);
});

app.post("/report", (req, res) => {
  const { text, result, score } = req.body || {};

  if (typeof text !== "string" || !text.trim()) {
    return res.status(400).json({
      error: 'The request body must include a non-empty "text" field.',
    });
  }

  const report = {
    timestamp: new Date().toISOString(),
    text,
    result: typeof result === "string" ? result : "Suspicious",
    score: typeof score === "number" ? score : null,
  };

  reportedItems.push(report);

  return res.json({
    message: "Reported for review.",
    report,
  });
});

app.get("/audit", (_req, res) => {
  res.json(auditLog);
});

app.get("/stats", (_req, res) => {
  const totalDetections = auditLog.filter(
    (entry) => entry.result === "Suspicious" || entry.result === "Likely Phishing"
  ).length;
  const brandCounts = {};

  auditLog.forEach((entry) => {
    (entry.impersonatedBrands || []).forEach((brand) => {
      brandCounts[brand] = (brandCounts[brand] || 0) + 1;
    });
  });

  const mostImpersonatedBrand = Object.entries(brandCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || "—";

  res.json({
    totalReports: reportedItems.length,
    totalAnalyses: auditLog.length,
    totalDetections,
    mostImpersonatedBrand,
  });
});

app.listen(PORT, () => {
  console.log("NoPhish server running on port 3000");
});
