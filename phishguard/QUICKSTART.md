# 🚀 Quick Start Checklist

Use this checklist to set up and run PhishGuard.

## ✅ Pre-Setup (Get API Keys - 10 minutes)

- [ ] **VirusTotal API Key**
  - Go to: https://www.virustotal.com/gui/join-us
  - Sign up (takes 2 min)
  - Copy API key from Profile → API Key

- [ ] **Google Safe Browsing API Key**
  - Go to: https://console.cloud.google.com
  - Create project
  - Enable "Safe Browsing API"
  - Create API Key

- [ ] **Gemini API Key**
  - Go to: https://aistudio.google.com/app/apikey
  - Click "Create API Key"
  - Copy key

## 🔧 Backend Setup (10 minutes)

```powershell
# 1. Navigate to backend
cd "C:\Users\nithishraju\Desktop\cyber project\phishguard\backend"

# 2. Create virtual environment
python -m venv venv

# 3. Activate it
.\venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Edit .env and paste your 3 API keys
notepad .env

# 6. Run backend
uvicorn main:app --reload --port 8000
```

**✅ You should see:**
```
INFO:     Uvicorn running on http://127.0.0.1:8000
```

## 🎨 Frontend Setup (5 minutes)

Open a **new terminal window** and run:

```powershell
# 1. Navigate to frontend
cd "C:\Users\nithishraju\Desktop\cyber project\phishguard\frontend"

# 2. Install dependencies
npm install

# 3. Start dev server
npm run dev
```

**✅ You should see:**
```
➜  Local:   http://localhost:5173/
```

## 🌐 Open the App

Open in browser: **http://localhost:5173**

## 🧪 Test It

### Test 1: Safe URL
1. Click "SCAN URL"
2. Enter: `https://www.google.com`
3. See GREEN gauge (SAFE)

### Test 2: Malicious URL
1. Enter: `http://malware.testing.google.test/testing/malware/`
2. See RED gauge (DANGEROUS)

### Test 3: Phishing Email
1. Click "ANALYZE EMAIL"
2. Paste:
```
From: security@paypa1.com
Subject: URGENT: Verify your account

Your PayPal account has been suspended.
Click NOW: http://fake-paypal-login.xyz

Enter your password and credit card.
```
3. See RED verdict (PHISHING)

## 🎯 That's It!

You now have a working threat detection system. 🛡️

---

## 📋 Running Anytime

Just run these two commands in separate terminals:

**Terminal 1:**
```powershell
cd backend && .\venv\Scripts\activate && uvicorn main:app --reload --port 8000
```

**Terminal 2:**
```powershell
cd frontend && npm run dev
```

---

## 🐛 Quick Troubleshooting

| Problem | Solution |
|---------|----------|
| Backend won't start | Check .env has all 3 API keys |
| npm not found | Install Node.js from nodejs.org |
| Port 8000 in use | Use `--port 8001` instead |
| Frontend can't connect | Check backend is running at :8000 |
| API key errors | Paste keys exactly as given (no spaces) |

---

## 📚 Documentation

- **README.md** — Full documentation & features
- **SETUP.md** — Detailed setup with troubleshooting
- **BUILD_SUMMARY.md** — Complete file structure & overview

---

**Questions?** Check the docs or test with the sample URLs provided.

**Ready to hunt phishing?** 🎯 Start scanning!
