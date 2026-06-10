# ScamGuard - Anti Scam Checker

ScamGuard is a Chrome/Edge extension that checks suspicious links, messages, emails, and the current web page for phishing/scam signals.

## What it does

- Scan the current page URL, selected text, page text, and visible links.
- Paste a suspicious message/link and scan manually.
- Highlight risky links on the current page.
- Show risk score: SAFE / LOW / MEDIUM / HIGH.
- Explain why something is risky in Vietnamese-friendly language.
- Save scan history locally in the browser.
- Runs locally. No API key, no server, no tracking.

## Install as unpacked extension

1. Extract this folder.
2. Open Chrome or Microsoft Edge.
3. Go to `chrome://extensions` or `edge://extensions`.
4. Turn on **Developer mode**.
5. Click **Load unpacked**.
6. Select the `scamguard-extension` folder.
7. Pin the ScamGuard icon to the toolbar.

## Usage

- Click the ScamGuard icon.
- Choose **Current page** then click **Scan current page**.
- Or choose **Paste text/link**, paste a suspicious message, then scan.
- Use **Highlight risky links** to outline suspicious links on the page.

## Important note

This is a rule-based assistant, not a final truth machine. It can produce false positives or miss new scam tricks. Always verify sensitive actions through official apps/websites.

## Suggested next upgrades

- Add OCR for screenshots.
- Add a custom whitelist/blacklist.
- Add local ML model or optional AI explanation.
- Add Vietnamese scam report export as PDF.
- Add Firefox version.
