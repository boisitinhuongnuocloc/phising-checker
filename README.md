# ScamGuard - Anti Phishing & Scam Checker

**A rule-based Chrome/Edge extension that detects phishing links, fraudulent messages, and scam signals locally in your browser—with zero API keys, zero servers, and zero tracking.**

---

## 📖 Project Overview

ScamGuard is a browser extension built to help Vietnamese users (and anyone) identify phishing attacks, scam links, and fraudulent messages before clicking on them or entering sensitive data. Unlike cloud-based solutions, it runs entirely client-side with a transparent, rule-based scoring engine—making it fast, privacy-friendly, and always available offline.

**Core Features:**
- ✅ Scan current page URL, selected text, page content, and visible links
- ✅ Paste suspicious messages/links and scan manually
- ✅ Highlight risky links directly on web pages
- ✅ Risk scoring: SAFE / LOW / MEDIUM / HIGH
- ✅ Detailed explanations in Vietnamese-friendly language
- ✅ Local scan history (up to 50 results stored in browser)
- ✅ No API keys, no server, no tracking—100% client-side

---

## 🏗️ Architecture

```
scamguard-extension/
├── manifest.json           # Extension configuration (Chrome Manifest v3)
├── popup.html              # Main UI (tabs, scan buttons, results display)
├── popup.css               # Dark-themed styling
├── options.html            # History page UI
├── src/
│   ├── scanner.js          # Core scoring engine (1000+ LOC)
│   ├── popup.js            # UI event handlers & render logic
│   ├── content.js          # Page injection for link highlighting
│   ├── background.js       # Service worker (placeholder)
│   ├── options.js          # History management
│   └── popup.css           # History page styles
└── icons/                  # 16x32x48x128 PNG icons
```

### Key Components

#### 1. **Scanner Engine** (`src/scanner.js`)
The heart of ScamGuard. A pure JavaScript rule-based scorer that analyzes text for phishing signals.

**Scoring Rules:**
- **URL Analysis:**
  - Missing HTTPS (10 pts)
  - Credentials in URL / @ symbol (25 pts)
  - IP address instead of domain (18 pts)
  - Punycode domain tricks (22 pts)
  - Shortened URL (16 pts)
  - Suspicious TLDs (.top, .xyz, .click, .icu, etc.) (10 pts)
  - Long/hyphenated domains (8 pts)
  - Credentials-related path (14 pts)

- **Brand Impersonation:**
  - Contains brand name but isn't official domain (+22 pts)
  - Tracks 40+ brands: Facebook, Google, Microsoft, Apple, PayPal, Shopee, banks (MB, Vietcombank, Techcombank, etc.)

- **Text Analysis:**
  - Scam keywords in Vietnamese & English (4-8 pts each)
  - Examples: "xác minh tài khoản", "verify your account", "mã OTP", "password reset"
  - Credential requests: "mật khẩu", "otp", "2fa" (15 pts)
  - Urgency patterns: "khẩn cấp", "ngay lập tức" (12 pts)
  - Reward bait: "trúng thưởng", "free gift" (12 pts)
  - Money/investment: "chuyển khoản", "crypto", "lãi suất cao" (14 pts)
  - Multiple URLs in content (8 pts)

**Score → Risk Level:**
- 0–19: SAFE
- 20–44: LOW
- 45–74: MEDIUM
- 75–100: HIGH

#### 2. **Popup UI** (`popup.html` + `popup.js`)
Two-tab interface for quick scanning:

**Tab 1: Current Page**
- Click **Scan current page** to analyze the active tab's URL, title, selected text, and all visible links
- Fallback for restricted pages (Chrome extensions, system pages) → only uses tab metadata

**Tab 2: Paste Text/Link**
- Paste suspicious messages, emails, links, or full message threads
- Click **Scan pasted content** to analyze

**Results Display:**
- Risk level badge (HIGH/MEDIUM/LOW/SAFE) with score (0–100)
- Animated score meter
- Detailed findings list (sorted by severity, max 20 items)
- Detected URLs with individual scores
- Recommended actions based on risk level
- Buttons to copy report or save to history

#### 3. **Content Script** (`src/content.js`)
Injected into web pages to:
- Extract page payload (title, URL, selected text, body text, up to 400 links)
- Highlight risky links with colored outlines (red for HIGH, yellow for MEDIUM)
- Respond to messaging from popup
- Support clearing highlights on demand

#### 4. **History Page** (`options.html` + `options.js`)
Displays up to 50 recent scans with:
- Risk level, score, summary
- Page URL (if page scan)
- Top 6 findings per entry
- Clear history button

---

## 🎯 How It Works

### User Flow

```
1. User clicks ScamGuard icon
   ↓
2. Choose: [Current page] or [Paste text/link]
   ↓
3. Click [Scan]
   ↓
4. Scanner analyzes against 100+ rules
   ↓
5. Display risk score + findings + recommendations
   ↓
6. (Optional) Save to history or copy report
```

### Example Scenarios

**Scenario 1: Fake Login Link**
```
Link: https://facebook-login.xyz/verify?user=admin
- No HTTPS ✓ (not actually HTTPS)
- Brand impersonation (facebook) ✓
- Suspicious TLD (.xyz) ✓
- Credential-related path (/verify) ✓
Score: 22 + 22 + 10 + 14 = 68 → MEDIUM
```

**Scenario 2: Phishing Message**
```
"Xác minh tài khoản Gmail ngay lập tức để tránh khóa tài khoản. 
Nhấn vào link: bit.ly/verify-now để xác nhận mật khẩu. 
Phí xác nhận: 50,000 VND"

Detections:
- "xác minh tài khoản" ✓ (8 pts)
- "ngay lập tức" (urgency) ✓ (12 pts)
- "khóa tài khoản" ✓ (8 pts)
- "mật khẩu" (credential term) ✓ (15 pts)
- "bit.ly" (shortener) ✓ (16 pts)
- "phí" (money) ✓ (14 pts)
Score: 8 + 12 + 8 + 15 + 16 + 14 = 73 → MEDIUM/HIGH
```

---

## 🚀 Installation & Usage

### Install as Unpacked Extension

1. **Extract** this repository folder
2. **Open** Chrome or Microsoft Edge
3. Go to `chrome://extensions` or `edge://extensions`
4. Toggle **Developer mode** (top right)
5. Click **Load unpacked**
6. Select the `scamguard-extension` folder
7. **Pin** the ScamGuard icon to your toolbar for easy access

### Daily Usage

- **Current Page**: Click icon → "Current page" tab → "Scan current page"
- **Paste & Scan**: Click icon → "Paste text/link" tab → paste suspicious message → scan
- **Highlight Links**: On any webpage, click "Highlight risky links" to visually mark dangerous URLs (red/yellow outlines)
- **View History**: Click the history link in the popup to review past scans

---

## 🔒 Privacy & Security

- ✅ **100% Client-Side**: All analysis runs in your browser
- ✅ **No Network Requests**: Zero tracking, no data sent anywhere
- ✅ **No API Keys**: No external dependencies
- ✅ **Local Storage Only**: History stored in browser's `chrome.storage.local`
- ✅ **Open Rules**: All detection logic is transparent and auditable

---

## 🧠 Key Design Decisions

### Why Rule-Based, Not ML/AI?

1. **Transparency**: Users can understand why something was flagged
2. **Speed**: No model loading or inference latency
3. **Offline**: Works without internet or API calls
4. **Auditability**: Easy to verify detection logic

### Vietnamese Localization

- 30+ Vietnamese scam terms built in
- Vietnamese bank domains (MB, VCB, TCB, Agri, etc.)
- Vietnamese payment apps (Momo, ZaloPay, Shopee, Lazada, Tiki)
- Localized UI and explanations
- Messages friendly to non-technical users

### Limitations (Acknowledged)

- **Rule-based false positives**: May flag legitimate but uncommon patterns
- **New scam tricks**: Rules can only catch known patterns
- **JavaScript obfuscation**: Can't detect obfuscated redirect scripts
- **Social engineering**: Can't judge human intent or context

**Recommendation**: Always verify sensitive actions through **official apps or websites**, not via links in messages.

---

## 🔄 Workflow: From Input to Score

```
Input (Text/URL)
    ↓
Extract URLs & Normalize Text
    ↓
URL Analysis (HTTPS, IP, punycode, shorteners, brand checks)
    ↓
Text Analysis (keywords, urgency, money, credentials)
    ↓
URL-to-Text Integration (boost text score based on URL findings)
    ↓
Clamp Score (0–100) & Assign Level (SAFE/LOW/MED/HIGH)
    ↓
Sort Findings by Severity & Points
    ↓
Generate Localized Summary & Recommendations
    ↓
Return Report {score, level, findings, urlReports, summary, recommendations}
```

---

## 📂 File Structure Breakdown

| File | Lines | Purpose |
|------|-------|---------|
| `scanner.js` | 363 | Core scoring engine, all detection rules |
| `popup.html` | 55 | Two-tab interface (current page / paste) |
| `popup.js` | 187 | Event handlers, scan logic, result rendering |
| `popup.css` | 175 | Dark theme, responsive layout |
| `content.js` | 76 | Page injection, link highlighting, messaging |
| `options.html` | 23 | History display page |
| `options.js` | 42 | History loading, clearing |
| `options.css` | 48 | History page styling |
| `manifest.json` | 42 | Extension metadata & permissions |

---

## 🎨 UI/UX Highlights

- **Dark theme** (blue accents): Reduces eye strain, modern look
- **Risk-colored badges**: Red (HIGH), Orange (MEDIUM), Light Blue (LOW), Green (SAFE)
- **Animated score meter**: Visual feedback during scanning
- **Scrollable findings**: Shows up to 20 issues per scan
- **Keyboard shortcut**: Ctrl/Cmd + Enter to scan from manual tab
- **Responsive design**: 390px wide popup fits Chrome sidebar
- **Accessible HTML**: Proper semantic markup, role attributes

---

## 🔧 Future Upgrade Ideas

- 📸 **OCR for Screenshots**: Analyze suspected scam screenshots
- ⚪ **Custom Whitelist/Blacklist**: User-defined safe/unsafe domains
- 🤖 **Optional Local ML**: TensorFlow.js micro-model for intent detection
- 📄 **PDF Export**: Export Vietnamese scam reports for reporting
- 🦊 **Firefox Version**: Adapt for Mozilla's extension API
- 🌐 **Multi-Language**: Expand beyond Vietnamese
- 🔗 **URL Redirect Tracing**: Follow shortened links safely
- 📊 **Telemetry Dashboard**: Anonymous aggregated stats (opt-in)

---

## ⚖️ Important Legal Note

**This is a rule-based assistant, not a final truth machine.** It can:
- ❌ Produce **false positives** (flag legitimate emails/links)
- ❌ Miss **new scam tricks** not covered by current rules
- ❌ Not guarantee 100% accuracy

**Always verify sensitive actions through:**
1. **Official apps or websites** (bookmark them or type directly)
2. **Official phone numbers** (from official website, not the message)
3. **Support channels** you know are genuine

ScamGuard is a **defense-in-depth tool**, not a replacement for caution and common sense.

---

## 📧 Support & Feedback

Found a false positive? A scam pattern we missed? Issues with installation?

Open an issue or discussion in the repository with:
- The suspicious link/text that was flagged (or not flagged)
- The score and findings it showed (or didn't)
- Your browser and OS version
- Whether it's a screenshot or live example

---

## 📜 License

[Specify your license here, e.g., MIT, GPL-3.0, etc.]

---

## 🙏 Disclaimer

This tool is provided **as-is** for educational and protective purposes. The developer is not responsible for:
- Damages from scams that bypass this tool
- False positives affecting legitimate communications
- Misuse of detection logic by bad actors

Use responsibly. Share the knowledge with non-technical friends and family to help them stay safe online.

---

**Last Updated:** June 2026  
**Version:** 1.0.0  
**Target Users:** Vietnamese internet users, anyone concerned about phishing
