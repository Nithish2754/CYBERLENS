import socket
import asyncio
import re

KNOWN_BAD_IP_RANGES = [
    "185.220.", "194.165.", "45.142.", "91.108.",
    "185.234.", "5.188.", "185.244."
]

BULLETPROOF_HOSTING = [
    "fortunix.net", "flokinet.is", "serverius.net"
]


async def check_dns_reputation(domain: str) -> dict:
    flags = []
    score = 0

    try:
        base = re.sub(r'^www\.', '', domain.split('/')[0])

        loop = asyncio.get_event_loop()
        ip = await loop.run_in_executor(
            None, socket.gethostbyname, base
        )

        # Check against known bad IP ranges
        for bad_range in KNOWN_BAD_IP_RANGES:
            if ip.startswith(bad_range):
                flags.append(f"IP address {ip} is in known malicious hosting range")
                score += 50
                break

        # Check if IP is from suspicious hosting
        try:
            hostname = await loop.run_in_executor(
                None, socket.gethostbyaddr, ip
            )
            host_str = str(hostname).lower()
            for bph in BULLETPROOF_HOSTING:
                if bph in host_str:
                    flags.append(f"Hosted on bulletproof hosting provider")
                    score += 40
                    break
        except Exception:
            pass

        return {
            "ip": ip,
            "dns_score": min(100, score),
            "flags": flags,
            "resolved": True
        }

    except socket.gaierror:
        return {
            "ip": "unresolvable",
            "dns_score": 30,
            "flags": ["Domain does not resolve — possibly fake or just registered"],
            "resolved": False
        }
    except Exception as e:
        return {"ip": "unknown", "dns_score": 0, "flags": [], "resolved": True}
