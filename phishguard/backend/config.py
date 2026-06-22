from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    VIRUSTOTAL_API_KEY: str
    SAFE_BROWSING_API_KEY: str
    GEMINI_API_KEY: str
    URLSCAN_API_KEY: str = ""
    IPQS_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    PHISHTANK_API_KEY: str = ""
    
    class Config:
        env_file = ".env"

settings = Settings()
