from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import url_scan, email_scan, security_audit

app = FastAPI(title="PhishGuard API", version="1.0.0")

# Configure CORS for frontend
# During local development allow all origins to avoid localhost/127.0.0.1/hostname mismatches.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(url_scan.router, prefix="/api")
app.include_router(email_scan.router, prefix="/api")
app.include_router(security_audit.router, prefix="/api")

@app.get("/")
async def root():
    """API health check."""
    return {"status": "PhishGuard API running", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    """Health check endpoint returning loaded API key state."""
    from config import settings
    return {
        "status": "running",
        "api_keys_configured": {
            "gemini": bool(settings.GEMINI_API_KEY),
            "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
            "safe_browsing": bool(settings.SAFE_BROWSING_API_KEY),
            "ipqs": bool(settings.IPQS_API_KEY),
            "urlscan": bool(settings.URLSCAN_API_KEY),
            "shodan": bool(settings.SHODAN_API_KEY) if hasattr(settings, 'SHODAN_API_KEY') else "N/A",
            "phishtank": bool(settings.PHISHTANK_API_KEY) if hasattr(settings, 'PHISHTANK_API_KEY') else False,
        }
    }
