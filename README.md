# NoPhish

NoPhish is a cybersecurity demo website for helping users identify possible phishing attempts from pasted URLs or email text.

## Features

- Express backend with heuristic phishing analysis
- Numeric risk scoring from `0` to `100`
- Level 4 domain similarity scoring to catch deceptive lookalike domains such as `g00gle.com`, `paypaI.com`, and `arnazon.com`
- Confidence breakdown showing how each signal added points
- Plain-English danger explanation for each analysis, including the suspected target brand and main phishing technique when available
- URL and domain checks for shortened links, insecure `http`, excessive subdomains, trusted-brand impersonation, and similarity-based brand lookalikes
- Attack type tags such as lookalike domains, brand impersonation, urgency language, shortened URLs, and insecure links
- Target-brand output so the frontend can show which trusted brand appears to be impersonated
- In-memory audit log for recent checks
- In-memory phishing reporting endpoint and Level 3 dashboard stats
- Security snapshot with total analyses, suspicious/phishing detections, reports, and most impersonated brand
- Recent security-event style activity feed limited to the latest 5 checks
- Demo scenario buttons for safe, suspicious, and likely phishing examples
- Plain HTML, CSS, and JavaScript frontend with result cards, audit history, and security dashboard polish

## Level 4 Features

- Domain similarity detection for trusted-brand lookalikes
- Weighted risk scoring with clear Safe, Suspicious, and Likely Phishing tiers
- Attack type classification for phishing techniques such as urgency language, credential harvesting, shortened URLs, and impersonation
- Security dashboard metrics including threat detections and most impersonated brand

## Level 5 Features

- Lightweight dashboard chart showing counts for Safe, Suspicious, and Likely Phishing analyses
- Recent Checks auto-refresh every 5 seconds with manual refresh still available
- Recent Checks filtering for All, Safe, Suspicious, and Likely Phishing events
- Exportable JSON analysis reports including score, attack types, reasons, breakdown, target brand, explanation, and timestamp
- Analyst Summary output for a concise SOC-style assessment of the latest analysis

## Run Locally

```bash
npm install
npm start
```

Then open `http://localhost:3000`.
