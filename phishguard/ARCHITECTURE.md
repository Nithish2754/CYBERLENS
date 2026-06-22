# PhishGuard — Architecture & Implementation Guide

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT (React)                            │
│                    http://localhost:5173                          │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Home Page        URLScan Page      EmailScan Page       │   │
│  │  (Landing)        (URL Analysis)    (Email Analysis)     │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────────┘
                         │ axios HTTP
         ┌───────────────┴────────────────┐
         ↓                                ↓
    /api/scan/url                   /api/scan/email
    
┌─────────────────────────────────────────────────────────────────┐
│                    SERVER (FastAPI)                              │
│                    http://localhost:8000                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  URL Router              Email Router                    │   │
│  │  ├─ Parse URL            ├─ Parse email                 │   │
│  │  ├─ Run checks           ├─ Extract URLs                │   │
│  │  └─ Combine results      └─ Run analysis                │   │
│  └──────────────────────────────────────────────────────────┘   │
│                           │                                      │
│  ┌────────────────────────┴──────────────────────────────┐      │
│  │              Services Layer                            │      │
│  │  ┌─────────────┐  ┌──────────┐  ┌─────────────────┐  │      │
│  │  │ VirusTotal  │  │Safe Brow-│  │ Gemini AI       │  │      │
│  │  │ Service     │  │sing Serv │  │ Service         │  │      │
│  │  └─────────────┘  └──────────┘  └─────────────────┘  │      │
│  │  ┌─────────────┐  ┌──────────────────────────────┐    │      │
│  │  │Threat Scorer│  │Email Parser                 │    │      │
│  │  └─────────────┘  └──────────────────────────────┘    │      │
│  └────────────────────────┬──────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         ↓               ↓               ↓
    VirusTotal       Google Safe      Gemini API
    API v3           Browsing API      1.5 Flash
```

---

## 📊 Data Flow

### URL Scanning Flow
```
1. User enters URL
2. Frontend validates URL format
3. POST to /api/scan/url with {url}
4. Backend:
   a. Normalize URL (add https:// if needed)
   b. Encode URL for VirusTotal lookup
   c. Call VirusTotal API (get malware detections)
   d. Call Safe Browsing API (get threat types)
   e. Run threat scorer (combine signals)
   f. Call Gemini AI (get explanation)
   g. Build response object
5. Frontend:
   a. Parse response
   b. Display threat gauge
   c. Show reasons & explanation
   d. Save to localStorage history
   e. Render result components
```

### Email Analysis Flow
```
1. User pastes email content
2. Frontend sends to /api/scan/email
3. Backend:
   a. Extract sender, subject with regex
   b. Extract all URLs from email body
   c. For each URL (max 3):
      - Call VirusTotal to check for malware
      - Store malicious count
   d. Call Gemini AI:
      - Analyze for phishing indicators
      - Return risk_score, verdict, indicators
   e. Run email threat scorer
   f. Build comprehensive response
4. Frontend displays:
   a. Verdict badge (Safe/Suspicious/Phishing)
   b. Threat gauge
   c. Email metadata
   d. AI analysis
   e. Threat indicators
   f. Extracted URLs table
```

---

## 🔄 Request/Response Cycle

### URL Scan Request
```json
{
  "url": "https://example.com"
}
```

### URL Scan Response
```json
{
  "url": "https://example.com",
  "threat_score": 0,
  "threat_level": "SAFE",
  "reasons": [
    "No threats detected across all security engines"
  ],
  "ai_explanation": "This URL appears to be a legitimate website...",
  "virustotal": {
    "malicious": 0,
    "suspicious": 0,
    "harmless": 95,
    "undetected": 2,
    "total_engines": 97,
    "reputation": 0,
    "categories": {},
    "title": "Example Domain"
  },
  "safe_browsing": {
    "is_threat": false,
    "threat_types": [],
    "platform_types": []
  },
  "timestamp": "2024-06-09T10:30:00.000Z"
}
```

### Email Analysis Request
```json
{
  "email_text": "From: sender@example.com\nSubject: Test\n..."
}
```

### Email Analysis Response
```json
{
  "metadata": {
    "sender": "sender@example.com",
    "subject": "Test Subject",
    "reply_to": null,
    "url_count": 1,
    "word_count": 50
  },
  "threat_score": 75,
  "threat_level": "HIGH RISK",
  "verdict": "Phishing",
  "summary": "This email exhibits classic phishing patterns...",
  "indicators": [
    "Urgency language (act now, verify immediately)",
    "Request for credentials or sensitive information",
    "Suspicious sender domain"
  ],
  "recommended_action": "Delete this email immediately and do not click any links",
  "extracted_urls": [
    {
      "url": "http://fake-site.com",
      "malicious": 3,
      "suspicious": 2,
      "total": 85
    }
  ],
  "reasons": [
    "3/85 security engines flagged as malicious",
    "2 engines marked as suspicious"
  ],
  "timestamp": "2024-06-09T10:30:00.000Z"
}
```

---

## 🎯 Component Hierarchy

```
App
├── Navbar
│   ├── Logo (Shield icon + Text)
│   ├── Navigation Links
│   └── Status Indicator
│
├── Home (/)
│   ├── Header Badge
│   ├── Main Heading
│   ├── Scan Buttons
│   ├── Stats Bar
│   └── Feature Cards
│
├── URLScan (/url)
│   ├── Header
│   ├── ScanInput
│   ├── ThreatGauge (if result)
│   ├── ResultCard (AI Assessment)
│   ├── ResultCard (Detection Breakdown)
│   ├── ResultCard (URL Details)
│   └── ScanHistory
│
└── EmailScan (/email)
    ├── Header
    ├── Textarea Input
    ├── Verdict Badge (if result)
    ├── ThreatGauge (if result)
    ├── Metadata Box (if result)
    ├── ResultCard (Summary)
    ├── ResultCard (Indicators)
    ├── ResultCard (Recommended Action)
    ├── ResultCard (Extracted URLs)
    └── ScanHistory
```

---

## 🔌 Service Dependencies

### VirusTotal Service
```python
scan_url(url: str) -> dict
├─ Encodes URL using base64
├─ Makes GET request to /urls/{url_id}
├─ Returns: malicious, suspicious, harmless, undetected counts
└─ Includes: reputation, categories, title
```

### Safe Browsing Service
```python
check_url(url: str) -> dict
├─ Creates threat request payload
├─ Makes POST to threatMatches:find endpoint
├─ Checks for: MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, etc.
└─ Returns: is_threat boolean, threat_types list
```

### Threat Scorer Service
```python
calculate_url_threat_score(vt: dict, sb: dict) -> dict
├─ Weights: Malicious (55%), Suspicious (20%), Bad Rep (15%), SB (30%)
├─ Combines signals from both APIs
├─ Returns: score (0-100), level, reasons
└─ Level map:
    0-20: SAFE
    21-40: LOW RISK
    41-65: MEDIUM RISK
    66-85: HIGH RISK
    86-100: CRITICAL THREAT

calculate_email_threat_score(ai_result: dict) -> dict
├─ Uses risk_score from AI
├─ Returns: score, level, reasons (indicators)
└─ Level map: Same as URL scoring
```

### AI Service
```python
analyze_url_ai(url, vt_result, sb_result) -> str
├─ Constructs prompt with:
│  ├─ URL
│  ├─ VT detection counts
│  ├─ Safe Browsing threats
│  └─ Reputation score
├─ Calls Gemini 1.5 Flash
├─ Returns: 2-3 sentence explanation
└─ Fallback: Generic explanation if API fails

analyze_email_ai(email_text: str) -> dict
├─ Constructs detailed prompt
├─ Specifies JSON response format
├─ Requests:
│  ├─ risk_score (0-100)
│  ├─ verdict (Safe/Suspicious/Phishing)
│  ├─ summary (2-3 sentences)
│  ├─ indicators (list of findings)
│  └─ recommended_action
├─ Parses JSON response
└─ Returns: dict with all fields
```

### Email Parser Service
```python
extract_urls_from_email(text: str) -> list
├─ Regex pattern: r'https?://[^\s<>"{}|\\^`\[\]]+'
└─ Returns: list of unique URLs

extract_email_metadata(text: str) -> dict
├─ Extracts: From, Subject, Reply-To headers
├─ Counts: URLs, words
└─ Returns: sender, subject, url_count, word_count
```

---

## 🎨 Frontend Component Props

### ThreatGauge
```jsx
<ThreatGauge
  score={0}        // 0-100 number
  level="SAFE"     // "SAFE" | "LOW RISK" | "MEDIUM RISK" | "HIGH RISK" | "CRITICAL THREAT"
/>
```

### ResultCard
```jsx
<ResultCard
  title="Title"           // string
  icon={IconComponent}    // lucide-react icon
  children={<Component/>} // any React node
  accentColor="#00d4ff"   // CSS color string
/>
```

### IndicatorList
```jsx
<IndicatorList
  indicators={[
    "Indicator 1",
    "Indicator 2"
  ]}
/>
```

### ScanInput
```jsx
<ScanInput
  url="https://..."       // string
  setUrl={setterFunc}    // state setter
  onScan={scanFunc}      // callback when scan button clicked
  loading={false}        // boolean
  placeholder="text"     // string
/>
```

### ScanHistory
```jsx
<ScanHistory
  history={[]}           // array of {url, threat_level, timestamp}
  onSelect={selectFunc}  // callback when history item selected
  onClear={clearFunc}    // callback when clear button clicked
/>
```

---

## 📈 Threat Scoring Algorithm

### URL Threat Score Calculation

```javascript
score = 0

// VirusTotal signals
if (malicious > 0) {
  score += min(55, malicious * 10)  // Up to 55 points
}
if (suspicious > 0) {
  score += min(20, suspicious * 4)  // Up to 20 points
}
if (reputation < -10) {
  score += 15                        // Up to 15 points
}

// Safe Browsing signals
if (is_threat) {
  score += 30                        // Up to 30 points
}

score = min(100, score)  // Cap at 100
```

### Level Mapping
- 0-20: SAFE (green)
- 21-40: LOW RISK (yellow-green)
- 41-65: MEDIUM RISK (yellow)
- 66-85: HIGH RISK (orange)
- 86-100: CRITICAL THREAT (red)

---

## 🔐 Error Handling

### Backend Error Handling
```python
# Timeouts
async with httpx.AsyncClient(timeout=15):  # 15 second timeout

# Retry logic
for attempt in range(2):
  try:
    response = await api_call()
    return response
  except Exception:
    if attempt == 0:
      await asyncio.sleep(2)  # Wait before retry

# Fallback responses
if api_fails:
  return default_safe_response()  # Assume safe if can't verify
```

### Frontend Error Handling
```javascript
try {
  const response = await axios.post(url, data)
  setResult(response.data)
} catch (error) {
  console.error(error)
  alert('Error: Check backend is running')
  // Don't set result, show error state
}
```

---

## 🚀 Performance Optimizations

1. **Concurrent API Calls**: asyncio.gather() for parallel requests
2. **Caching**: Browser localStorage for history
3. **Async Processing**: No blocking operations
4. **Lazy Loading**: Components load only when needed
5. **Debouncing**: Input validation before API calls
6. **Connection Pooling**: httpx AsyncClient reused

---

## 📱 Responsive Design

- Mobile-first approach
- Tailwind breakpoints:
  - `md:` (768px+) for desktop layouts
  - Stack layouts on mobile
- Touch-friendly button sizes (40px+ height)

---

## 🔧 Extensibility Points

### Add New Threat Source
1. Create `services/newsource_service.py`
2. Add function `check_url_newsource(url: str) -> dict`
3. Update `routers/url_scan.py` to call it
4. Update threat scorer to weight it

### Add Email Integration
1. Create `services/email_service.py`
2. Add function `get_emails()` for IMAP/API connection
3. Create `routers/email_fetch.py`
4. Add UI component for selecting emails

### Add Database Storage
1. Setup SQLAlchemy models
2. Replace localStorage with database queries
3. Create `services/database.py`
4. Add user authentication

### Add Bulk Scanning
1. Create batch endpoint `/api/scan/urls/batch`
2. Accept array of URLs
3. Return array of results
4. Add progress indicator in UI

---

## 📚 API Integration Details

### VirusTotal API
- Base: `https://www.virustotal.com/api/v3`
- Auth: Header `x-apikey: {key}`
- Endpoint: `GET /urls/{url_id}` (url_id is base64 encoded)
- Rate: 500 requests/day (free)

### Google Safe Browsing API
- Base: `https://safebrowsing.googleapis.com/v4`
- Auth: Query param `key={key}`
- Endpoint: `POST /threatMatches:find`
- Rate: 10,000 requests/day (free)

### Gemini API
- Base: `https://generativelanguage.googleapis.com`
- Auth: Header `Authorization: Bearer {key}`
- Model: `gemini-1.5-flash`
- Rate: 60 requests/minute (free)

---

## 🧪 Testing Guide

### Unit Testing
```python
# tests/test_threat_scorer.py
def test_safe_url_scoring():
  vt = {"malicious": 0, "suspicious": 0, "total_engines": 90}
  sb = {"is_threat": False, "threat_types": []}
  result = calculate_url_threat_score(vt, sb)
  assert result["score"] == 0
  assert result["level"] == "SAFE"
```

### Integration Testing
```javascript
// tests/URLScan.test.jsx
test('displays green gauge for safe URL', async () => {
  render(<URLScan />)
  const input = screen.getByPlaceholderText(/Enter URL/)
  userEvent.type(input, 'https://google.com')
  userEvent.click(screen.getByText('SCAN'))
  await waitFor(() => {
    expect(screen.getByText('SAFE')).toBeInTheDocument()
  })
})
```

---

**PhishGuard Architecture Summary**: A distributed, async-first system with clear separation between threat intelligence services, threat scoring logic, and UI presentation. Highly scalable and maintainable.
