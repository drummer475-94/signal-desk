# Signal Desk

[![Tests](https://github.com/drummer475-94/signal-desk/actions/workflows/pages.yml/badge.svg)](https://github.com/drummer475-94/signal-desk/actions/workflows/pages.yml)

Signal Desk is a static, browser-native security log triage workbench. It accepts JSON, JSONL, and CSV evidence; normalizes common field names; runs transparent correlation rules; and exports analyst decisions with the supporting events.

**[Open the live app](https://drummer475-94.github.io/signal-desk/)**

## 60-second review

1. Start with the demo case and scan the two critical findings in the summary.
2. Open **Successful sign-in after failure burst** to see the correlated evidence and recommended response.
3. Record an escalation note, search the normalized event stream, and export the evidence-backed case.

The implementation is framework-free, has no runtime dependencies, processes evidence locally, and isolates its tested parsing and detection rules in [`core.js`](core.js).

## Why this project exists

The app demonstrates security operations work that is visible in the product: evidence ingestion, schema normalization, event correlation, incident triage, privacy-aware processing, accessible interaction, and testable detection logic. It complements—rather than duplicates—the existing weather, network-visibility, and cybersecurity research projects in this portfolio.

## Features

- Local-only processing with a 5 MB import limit
- JSON, JSONL, and quoted CSV parsing
- Authentication-burst and failure-then-success correlation
- Privileged-role, encoded PowerShell, malware, and disabled-account rules
- Search and source/severity filters
- Analyst decisions and notes stored in local browser storage
- JSON case export with linked evidence and rule guidance
- Responsive table/card layout and keyboard-accessible finding dialog

Detection results are intentionally described as heuristic findings. They require validation and are not presented as a substitute for a SIEM or incident-response process.

## Professional grounding

- [NIST NICE Workforce Framework](https://csrc.nist.gov/pubs/sp/800/181/r1/final) tasks include multi-source log analysis, cyber-defense triage, trend analysis, and event correlation.
- [CISA logging and monitoring guidance](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems) emphasizes collecting useful detail, centralizing logs, and reviewing high-risk events.

## Run and verify

Serve this directory with any static server. No build step or third-party runtime dependency is required.

```powershell
npm run check
npm test
python -m http.server 4173
```

Then open `http://localhost:4173`.

## GitHub Pages

The workflow in `.github/workflows/pages.yml` publishes the repository root. Create a GitHub repository, push this project to `main`, and set **Settings → Pages → Source** to **GitHub Actions**.
