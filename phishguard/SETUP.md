# PhishGuard Setup Guide

## 🔑 Step 1: Get API Keys (5 minutes)

### 1.1 VirusTotal API Key
1. Visit: https://www.virustotal.com/gui/join-us
2. Sign up for free account
3. Go to Profile → API Key
4. Copy your API key

### 1.2 Google Safe Browsing API Key
1. Visit: https://console.cloud.google.com
2. Create new project
3. Enable "Safe Browsing API"
4. Go to Credentials → Create API Key
5. Copy your API key

### 1.3 Gemini API Key
1. Visit: https://aistudio.google.com/app/apikey
2. Click "Create API Key"
3. Copy your API key

---

## 🖥️ Step 2: Backend Setup (5 minutes)

### 2.1 Open Terminal/PowerShell

On Windows: Press `Win+R`, type `powershell`, press Enter

### 2.2 Navigate to Backend
```powershell
cd "C:\Users\nithishraju\Desktop\cyber project\phishguard\backend"
```

### 2.3 Create Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\activate
```

### 2.4 Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2.5 Add Your API Keys to .env

Open `.env` file in the backend folder:
```
VIRUSTOTAL_API_KEY=paste_your_virustotal_key_here
SAFE_BROWSING_API_KEY=paste_your_google_key_here
GEMINI_API_KEY=paste_your_gemini_key_here
```

### 2.6 Start Backend Server
```powershell
uvicorn main:app --reload --port 8000
```

You should see:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
```

✅ **Backend is running!**

Test it: Open http://localhost:8000/docs in browser

---

## 🎨 Step 3: Frontend Setup (5 minutes)

### 3.1 Open New Terminal/PowerShell

Press `Ctrl+Shift+P` → "Terminal: Create New Terminal" (or open new window)

### 3.2 Navigate to Frontend
```powershell
cd "C:\Users\nithishraju\Desktop\cyber project\phishguard\frontend"
```

### 3.3 Install Dependencies
```powershell
npm install
```

This will download all React packages (~300 MB, takes 1-2 minutes)

### 3.4 Start Frontend Server
```powershell
npm run dev
```

You should see:
```
VITE v5.3.3  ready in 234 ms

➜  Local:   http://localhost:5173/
```

✅ **Frontend is running!**

---

## 🚀 Step 4: Open the App

Open your browser to: **http://localhost:5173**

You should see the PhishGuard home page with:
- Logo and title
- Two buttons: "SCAN URL" and "ANALYZE EMAIL"
- Feature cards explaining the tool

---

## 🧪 Step 5: Test the App

### Test URL Scanner
1. Click "SCAN URL"
2. Paste: `https://www.google.com`
3. Click "SCAN"
4. You should see:
   - Green threat gauge (SAFE)
   - AI assessment
   - VirusTotal results

### Test Email Analyzer
1. Click "ANALYZE EMAIL"
2. Paste this phishing email:
   ```
   From: security@paypa1.com
   Subject: URGENT: Verify your PayPal account

   Dear Customer,
   Your account has been suspended.
   Click here NOW to verify: http://paypal-verify-fake.xyz

   Enter your password and card number.
   ```
3. Click "ANALYZE THREAT"
4. You should see:
   - Red/orange threat gauge (SUSPICIOUS/PHISHING)
   - Phishing indicators highlighted
   - Recommended action

---

## 📋 Running Both Together (Quick Reference)

### Terminal 1 - Backend
```powershell
cd backend
.\venv\Scripts\activate
uvicorn main:app --reload --port 8000
```

### Terminal 2 - Frontend
```powershell
cd frontend
npm run dev
```

### Browser
Open: http://localhost:5173

---

## 🔧 Troubleshooting

### Problem: "ModuleNotFoundError" when running backend
**Solution:**
```powershell
# Make sure venv is activated (should see (venv) prefix)
.\venv\Scripts\activate
pip install -r requirements.txt
```

### Problem: "npm not found"
**Solution:**
- Install Node.js from: https://nodejs.org (LTS version)
- Restart PowerShell after installing

### Problem: "API key errors"
**Solution:**
- Check .env file has correct keys (no extra spaces)
- Make sure keys are pasted correctly
- Check API is enabled in Google Cloud Console

### Problem: Frontend can't reach backend
**Solution:**
1. Check backend is running on port 8000
2. Check CORS is enabled (it should be by default)
3. Try: http://localhost:8000/docs in browser to test API

### Problem: Port 8000 already in use
**Solution:**
```powershell
# Use different port
uvicorn main:app --reload --port 8001
# Then update frontend API_BASE in pages/URLScan.jsx and EmailScan.jsx
```

---

## 📦 Project Files Created

✅ Backend
- `config.py` — Settings and API key loading
- `main.py` — FastAPI app setup
- `services/` — All API integration services
- `routers/` — URL and email scanning endpoints
- `requirements.txt` — Dependencies
- `.env` — API keys (you fill this in)

✅ Frontend
- `App.jsx` — Main router
- `components/` — Reusable UI components
- `pages/` — Home, URLScan, EmailScan pages
- `index.css` — Cyber theme styling
- `tailwind.config.js` — Tailwind configuration
- `package.json` — React dependencies

---

## 🎯 What's Next?

1. **Add more threat indicators** — Customize phishing detection
2. **Add database** — Store scan history permanently
3. **Add email file upload** — Drag & drop .eml files
4. **Add dark web monitoring** — Check for leaked credentials
5. **Add bulk scanning** — Scan multiple URLs at once
6. **Deploy to cloud** — Use Vercel (frontend) + Railway/Render (backend)

---

## 💡 Tips

- **Bookmark API docs:** http://localhost:8000/docs (interactive API testing)
- **Test malware URL:** http://malware.testing.google.test/testing/malware/
- **Check scan history:** Uses localStorage in browser dev tools
- **Customize colors:** Edit `frontend/src/index.css`

---

**✅ Setup Complete!** You now have a fully working cybersecurity threat analyzer. 🛡️

Questions? Check the README.md or test with the example URLs/emails provided.
