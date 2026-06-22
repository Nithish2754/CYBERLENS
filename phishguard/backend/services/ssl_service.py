import ssl
import socket
import asyncio
from datetime import datetime
from urllib.parse import urlparse


async def analyze_ssl(url: str) -> dict:
    flags = []
    score = 0

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "")

        # HTTP = no SSL at all
        if parsed.scheme == "http":
            return {
                "has_ssl": False,
                "flags": ["No SSL certificate — all data transmitted unencrypted"],
                "ssl_score": 30,
                "valid": False
            }

        loop = asyncio.get_event_loop()

        def get_cert():
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return ssock.getpeercert()

        try:
            cert = await loop.run_in_executor(None, get_cert)

            # Check expiry
            expire_str = cert.get("notAfter", "")
            days_left = None
            if expire_str:
                try:
                    expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expire_date - datetime.utcnow()).days
                    if days_left < 0:
                        flags.append("SSL certificate has EXPIRED")
                        score += 40
                    elif days_left < 15:
                        flags.append(f"SSL certificate expires in {days_left} days")
                        score += 20
                except Exception:
                    pass

            # Check issuer
            issuer = dict(x[0] for x in cert.get("issuer", []))
            org = issuer.get("organizationName", "")
            if not org or org in ["", "Unknown"]:
                flags.append("SSL issued by unknown/unverified authority")
                score += 15

            # Check if domain matches cert
            subject = dict(x[0] for x in cert.get("subject", []))
            common_name = subject.get("commonName", "")
            if common_name and domain not in common_name and common_name not in domain:
                flags.append(f"SSL certificate domain mismatch: cert is for '{common_name}'")
                score += 35

            return {
                "has_ssl": True,
                "issuer": org,
                "expires": expire_str,
                "days_remaining": days_left if expire_str else "unknown",
                "common_name": common_name,
                "flags": flags,
                "ssl_score": min(100, score),
                "valid": score == 0,
                "available": True
            }

        except ssl.SSLCertVerificationError as e:
            print(f"SSL verification error: {e}")
            return {
                "has_ssl": True,
                "flags": ["SSL certificate is INVALID or self-signed"],
                "ssl_score": 45,
                "valid": False,
                "available": True,
                "error": str(e)
            }
        except Exception as e:
            print(f"SSL check exception: {type(e).__name__}: {e}")
            return {
                "has_ssl": False,
                "flags": ["Could not verify SSL certificate"],
                "ssl_score": 15,
                "valid": False,
                "available": False,
                "error": str(e)
            }

    except Exception as e:
        print(f"SSL check error: {type(e).__name__}: {e}")
        return {
            "has_ssl": parsed.scheme == "https" if 'parsed' in locals() else False,
            "flags": [],
            "ssl_score": 0,
            "valid": parsed.scheme == "https" if 'parsed' in locals() else False,
            "available": False,
            "error": str(e)
        }
