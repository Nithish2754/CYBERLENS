# PhishGuard — AI-Powered Cybersecurity Threat Analyzer

A full-stack cybersecurity web application for detecting and analyzing phishing threats in URLs and emails.

## 🛡️ Features

- **URL Threat Scanner**: Analyze any URL against 90+ security engines
- **Email Phishing Detector**: Deep analysis of email content for phishing patterns
- **AI-Powered Analysis**: Gemini AI provides intelligent threat assessment
- **Multi-Source Intelligence**: VirusTotal + Google Safe Browsing + Gemini API
- **Cyber Aesthetic UI**: Dark-themed, hacker-style interface with glowing effects
- **Real-time Threat Scoring**: Instant risk assessment (0-100)
- **Scan History**: Track your previous scans

## 🎯 Tech Stack

### Backend
- **FastAPI** — async Python web framework
- **VirusTotal API v3** — malware detection
- **Google Safe Browsing API v4** — threat detection
- **Gemini AI 1.5 Flash** — natural language threat analysis
- **HTTPX** — async HTTP client

### Frontend
- **React 18** + Vite
- **React Router** — navigation
- **Tailwind CSS** — styling
- **Recharts** — threat gauge visualization
- **Framer Motion** — smooth animations
- **Lucide React** — icons
- **Axios** — API communication

### Storage
- **localStorage** — scan history (no database needed)

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- npm or yarn
- API Keys (free):
  - VirusTotal: https://www.virustotal.com/gui/join-us
  - Google Safe Browsing: https://console.cloud.google.com (enable API)
  - Gemini API: https://aistudio.google.com/app/apikey

### Backend Setup

1. **Navigate to backend directory**
   ```bash
   cd backend
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**
   ```
   Edit .env and add your API keys:
   VIRUSTOTAL_API_KEY=your_key
   SAFE_BROWSING_API_KEY=your_key
   GEMINI_API_KEY=your_key
   ```

5. **Run backend**
   ```bash
   uvicorn main:app --reload --port 8000
   ```
   - API runs at: http://localhost:8000
   - API docs at: http://localhost:8000/docs

### Frontend Setup

1. **Navigate to frontend directory**
   ```bash
   cd frontend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Run development server**
   ```bash
   npm run dev
   ```
   - App runs at: http://localhost:5173

## 📡 API Endpoints

### URL Scanning
```
POST /api/scan/url
Body: {"url": "https://example.com"}
Response: {
  "url": "https://example.com",
  "threat_score": 0,
  "threat_level": "SAFE",
  "reasons": [...],
  "ai_explanation": "...",
  "virustotal": {...},
  "safe_browsing": {...}
}
```

### Email Analysis
```
POST /api/scan/email
Body: {"email_text": "From: sender@example.com\nContent..."}
Response: {
  "metadata": {...},
  "threat_score": 50,
  "threat_level": "MEDIUM RISK",
  "verdict": "Suspicious",
  "summary": "...",
  "indicators": [...],
  "recommended_action": "...",
  "extracted_urls": [...]
}
```

## 🧪 Testing

### Test URLs
- Safe: https://www.google.com
- Malware test: http://malware.testing.google.test/testing/malware/

### Test Email
Paste in Email Scanner:
```
From: security@paypa1.com
Subject: URGENT: Your account has been suspended

Dear Customer,
Your PayPal account has been temporarily suspended.
Click here immediately to verify: http://paypal-verify.suspicious.xyz

Enter your password and credit card to restore access.
```

## 🎨 UI Features

- **Threat Gauge**: Radial chart showing threat level (0-100)
- **Color Coding**: 
  - Green (#00ff88) = Safe
  - Yellow (#ffd700) = Medium Risk
  - Red (#ff0040) = Critical Threat
- **Glow Effects**: Neon cyan glow on hover
- **Animations**: Smooth fade-ins and scanning effects
- **Responsive**: Works on desktop and mobile

## 📁 Project Structure

```
phishguard/
├── backend/
│   ├── main.py
│   ├── config.py
│   ├── services/
│   │   ├── virustotal_service.py
│   │   ├── safebrowsing_service.py
│   │   ├── ai_service.py
│   │   ├── threat_scorer.py
│   │   └── email_parser.py
│   ├── routers/
│   │   ├── url_scan.py
│   │   └── email_scan.py
│   ├── requirements.txt
│   └── .env
│
└── frontend/
    ├── src/
    │   ├── components/
    │   │   ├── Navbar.jsx
    │   │   ├── ThreatGauge.jsx
    │   │   ├── ResultCard.jsx
    │   │   ├── IndicatorList.jsx
    │   │   ├── ScanInput.jsx
    │   │   └── ScanHistory.jsx
    │   ├── pages/
    │   │   ├── Home.jsx
    │   │   ├── URLScan.jsx
    │   │   └── EmailScan.jsx
    │   ├── App.jsx
    │   ├── main.jsx
    │   └── index.css
    ├── vite.config.js
    ├── tailwind.config.js
    └── package.json
```

## 🔐 Security Notes

- All API keys are stored in `.env` (never commit)
- CORS configured for localhost:5173 only
- No database — scan history stored in browser localStorage
- Email content never stored on server

## 📊 Threat Scoring

### URL Threat Score (0-100)
- 0-20: SAFE
- 21-40: LOW RISK
- 41-65: MEDIUM RISK
- 66-85: HIGH RISK
- 86-100: CRITICAL THREAT

### Email Threat Score (0-100)
- 0-20: SAFE
- 21-40: LOW RISK
- 41-65: MEDIUM RISK
- 66-85: HIGH RISK
- 86-100: CRITICAL THREAT

## 🐛 Troubleshooting

**Backend errors?**
- Check API keys in `.env`
- Ensure uvicorn is running on port 8000
- Check CORS settings if frontend can't reach backend

**Frontend won't load?**
- Check npm is installed: `npm --version`
- Clear node_modules: `rm -rf node_modules && npm install`
- Check Vite is running on port 5173

**No API key free tier?**
- All three APIs have generous free tiers
- VirusTotal: 500 lookups/day
- Safe Browsing: 10,000 requests/day
- Gemini API: 60 requests/minute

## 📝 License

MIT — Free to use and modify

---

Built with ❤️ for cybersecurity threat intelligence
