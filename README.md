# NoPhish

NoPhish is a cybersecurity demo website for helping users identify possible phishing attempts from pasted URLs or email text.

## Features

- Express backend with heuristic phishing analysis
- Numeric risk scoring from `0` to `100`
- Confidence breakdown showing how each signal added points
- Plain-English danger explanation for each analysis
- URL and domain checks for shortened links, insecure `http`, excessive subdomains, and trusted-brand impersonation
- Attack type tags such as lookalike domains, brand impersonation, urgency language, shortened URLs, and insecure links
- In-memory audit log for recent checks
- In-memory phishing reporting endpoint and Level 3 dashboard stats
- Security snapshot with total analyses, suspicious/phishing detections, reports, and most impersonated brand
- Recent security-event style activity feed limited to the latest 5 checks
- Demo scenario buttons for safe, suspicious, and likely phishing examples
- Plain HTML, CSS, and JavaScript frontend with result cards, audit history, and security dashboard polish

## Run Locally

```bash
npm install
npm start
```

Then open `http://localhost:3000`.
