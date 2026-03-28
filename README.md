# NoPhish

NoPhish is a cybersecurity demo website for helping users identify possible phishing attempts from pasted URLs or email text.

## Features

- Express backend with heuristic phishing analysis
- Numeric risk scoring from `0` to `100`
- Confidence breakdown showing how each signal added points
- Plain-English danger explanation for each analysis
- URL and domain checks for shortened links, insecure `http`, excessive subdomains, and trusted-brand impersonation
- In-memory audit log for recent checks
- In-memory phishing reporting endpoint and simple security stats
- Plain HTML, CSS, and JavaScript frontend with result cards, audit history, and stats

## Run Locally

```bash
npm install
npm start
```

Then open `http://localhost:3000`.
