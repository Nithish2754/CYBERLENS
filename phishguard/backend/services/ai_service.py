import google.generativeai as genai
from config import settings
import json
import asyncio

MODEL_NAMES = ["gemini-2.0-flash", "gemini-2.0-flash-lite", "gemini-1.5-flash-latest", "gemini-1.5-pro-latest", "gemini-pro"]

genai.configure(api_key=settings.GEMINI_API_KEY)

async def analyze_url_ai(
    url: str,
    vt: dict,
    sb: dict,
    pattern_flags: list = None,
    dns_result: dict = None,
    domain_result: dict = None,
    threat_score: float = None,
    threat_level: str = None,
) -> str:
    """Analyze URL using Gemini AI with all available signals."""
    if pattern_flags is None:
        pattern_flags = []
    if dns_result is None:
        dns_result = {}
    if domain_result is None:
        domain_result = {}

    all_flags = pattern_flags + dns_result.get('flags', []) + domain_result.get('flags', [])
    masked_key = settings.GEMINI_API_KEY[:8] + ('*' * max(len(settings.GEMINI_API_KEY) - 8, 0))
    print(f"GEMINI_API_KEY loaded: {masked_key}")

    prompt = f"""
You are a senior threat intelligence analyst at a cybersecurity firm.
Analyze this URL with ALL available data and give a definitive verdict.

TARGET URL: {url}

DETECTION DATA:
- VirusTotal engines flagged: {vt.get('malicious', 0)}/{vt.get('total_engines', 0)}
- Google Safe Browsing: {'THREAT DETECTED: ' + str(sb.get('threat_types')) if sb.get('is_threat') else 'Clean'}
- Pattern analysis flags: {len(all_flags)} suspicious indicators found
- Specific flags: {', '.join(all_flags[:5]) if all_flags else 'None'}
- DNS resolution: {dns_result.get('ip', 'unknown')}
- Final calculated threat level: {threat_level or 'UNKNOWN'} (score: {threat_score if threat_score is not None else 'N/A'}/100)

CRITICAL NOTE: The AI verdict must align with the final calculated threat level.
If the threat level is SAFE, your verdict must be SAFE.
If the threat level is CRITICAL THREAT, your verdict must reflect serious risk.

Analyze in exactly this format:

THREAT ASSESSMENT: [1-2 sentences on overall threat level]
KEY INDICATORS: [1-2 sentences on the most suspicious signals]  
RECOMMENDATION: [One clear action for the user]
VERDICT: [SAFE / LOW RISK / SUSPICIOUS / HIGH RISK / PHISHING]
"""
    # Stronger instruction to the model to produce a deterministic, aligned summary
    prompt = (
        prompt +
        "\nADDITIONAL INSTRUCTIONS: Respond in plain text (no markdown). Produce exactly 4 short sentences total. "
        "Sentence 1 must start with 'THREAT ASSESSMENT:' and match the numeric score/level provided. "
        "Sentence 2 must start with 'KEY INDICATORS:' listing up to 3 top signals. "
        "Sentence 3 must start with 'RECOMMENDATION:' and give one prioritized remediation. "
        "Sentence 4 must start with 'VERDICT:' and be one of SAFE / LOW RISK / SUSPICIOUS / HIGH RISK / PHISHING."
    )

    for model_name in MODEL_NAMES:
        print(f"Trying Gemini model: {model_name}")
        try:
            model = genai.GenerativeModel(model_name)
        except Exception as e:
            print(f"Gemini model init error for {model_name}: {type(e).__name__}: {e}")
            continue

        for attempt in range(2):
            try:
                response = model.generate_content(prompt)
                print(f"Gemini SUCCESS ({model_name}, attempt {attempt + 1}): {response.text[:200]}")
                return response.text.strip()
            except Exception as e:
                print(f"Gemini ERROR ({model_name}, attempt {attempt + 1}): {type(e).__name__}: {e}")
                if attempt == 0:
                    await asyncio.sleep(2)

    print("Gemini failed both attempts for all models, using fallback")
    if len(all_flags) == 0 and vt.get('malicious', 0) == 0 and not sb.get('is_threat'):
        return (
            "THREAT ASSESSMENT: No threats detected across all security sources. "
            "This URL appears safe based on available data.\n"
            "RECOMMENDATION: No immediate action needed.\n"
            "VERDICT: SAFE"
        )
    elif len(all_flags) >= 3:
        return (
            "THREAT ASSESSMENT: Multiple suspicious indicators detected. "
            f"KEY INDICATORS: {all_flags[0]}.\n"
            "RECOMMENDATION: Avoid this URL.\n"
            "VERDICT: HIGH RISK"
        )
    else:
        return (
            "THREAT ASSESSMENT: Minimal risk signals detected. "
            "Proceed normally, no major concerns found.\n"
            "RECOMMENDATION: Continue with standard caution.\n"
            "VERDICT: LOW RISK"
        )


async def analyze_email_ai(email_text: str) -> dict:
    """Analyze email using Gemini AI for phishing detection."""
    prompt = f"""
You are an EXTREMELY AGGRESSIVE phishing detection expert. Your job is to catch phishing emails.
Return ONLY valid JSON, no markdown, no extra text.

Email:
{email_text[:3000]}

SCORING INSTRUCTIONS:
- risk_score 0-30: SAFE (legitimate business emails only)
- risk_score 31-60: SUSPICIOUS (some red flags)
- risk_score 61-100: PHISHING (multiple red flags or obvious phishing)

Return EXACTLY (no other text):
{{
  "risk_score": <integer 0-100>,
  "verdict": "<Safe|Suspicious|Phishing>",
  "summary": "<2-3 sentence analysis>",
  "indicators": ["<specific red flag>", "<specific red flag>", "<specific red flag>"],
  "recommended_action": "<clear action: Delete|Report as Spam|Do Not Click Links>"
}}

AUTOMATIC PHISHING TRIGGERS (score >= 75):
- Urgency language: act now, verify immediately, account suspended, 24 hours, at risk
- Credential requests: password, verify account, confirm identity, credit card, SSN
- Spoofed sender: email domain doesn't match company name
- Suspicious URLs: bit.ly shorteners, mismatched domains, unusual TLDs
- Grammar/spelling errors in official email
- Impersonation: PayPal, Amazon, Apple, Microsoft, IRS, Banks, Google
- Threats: account closure, legal action, payment failure
- Multiple red flags = definitely PHISHING (score 80-100)

AUTOMATIC SUSPICIOUS (score 40-75):
- One or two minor red flags
- Unusual sender but not clearly spoofed
- One credential request without urgency

SAFE (score 0-30):
- Legitimate company domain
- No credential requests
- No urgency language
- Professional tone
- Clear purpose

IMPORTANT: If ANY phishing trigger exists, MINIMUM score is 60. If 2+ triggers exist, MINIMUM score is 80.
When in doubt, DEFAULT to PHISHING verdict. False positive > false negative.
"""
    for model_name in MODEL_NAMES:
        try:
            model = genai.GenerativeModel(model_name)
        except Exception as e:
            print(f"Gemini model init error for {model_name}: {type(e).__name__}: {e}")
            continue

        for attempt in range(2):
            try:
                response = model.generate_content(prompt)
                text = response.text.strip().replace("```json", "").replace("```", "").strip()
                return json.loads(text)
            except Exception as e:
                print(f"Email AI analysis error ({model_name}, attempt {attempt + 1}): {e}")
                if attempt == 0:
                    await asyncio.sleep(2)

    print("Email AI analysis: Gemini failed for all models, using deterministic fallback")
    return {
        "risk_score": 50,
        "verdict": "Suspicious",
        "summary": "Analysis incomplete. Exercise caution with this email.",
        "indicators": ["Could not fully analyze — treat with caution"],
        "recommended_action": "Do not click any links. Verify sender independently."
    }


async def summarize_security_audit(audit_result: dict) -> str:
    """Summarize security audit findings using AI."""
    findings_text = "\n".join([
        f"- [{f['severity']}] {f['issue']}" 
        for f in audit_result.get('findings', [])[:8]
    ])
    
    prompt = f"""
You are a cybersecurity consultant. A website was just audited with 
the following results:

Security Score: {audit_result.get('security_score')}/100 (Grade: {audit_result.get('grade')})
Total Issues Found: {audit_result.get('total_issues')}

Issues:
{findings_text}

Write a 3-4 sentence executive summary explaining the overall security 
posture of this website in plain English, what the biggest risk is, 
and what should be fixed first. Be constructive and professional, 
this is a legitimate business being audited, not an attack target.
"""
    
    for model_name in MODEL_NAMES:
        try:
            model = genai.GenerativeModel(model_name)
            response = model.generate_content(prompt)
            print(f"Security audit summary SUCCESS ({model_name})")
            return response.text.strip()
        except Exception as e:
            print(f"Security audit summary error ({model_name}): {type(e).__name__}: {e}")
    
    print("Security audit summary: Gemini failed, using fallback")
    # Deterministic fallback summary built from audit results so output is meaningful
    score = audit_result.get('security_score', 'N/A')
    grade = audit_result.get('grade', 'N/A')
    high_count = audit_result.get('high_severity_count', 0)
    med_count = audit_result.get('medium_severity_count', 0)
    low_count = audit_result.get('low_severity_count', 0)

    findings = audit_result.get('findings', [])
    top_high = [f for f in findings if f.get('severity') == 'HIGH']
    top_med = [f for f in findings if f.get('severity') == 'MEDIUM']

    parts = []
    parts.append(f"Overall grade is {grade} ({score}/100).")

    if high_count > 0:
        top_issues = ", ".join([f.get('issue') for f in top_high[:2]])
        parts.append(f"Critical issues detected: {top_issues}.")
        # recommend first high-priority remediation
        first_rec = top_high[0].get('recommendation') if top_high and top_high[0].get('recommendation') else None
        if first_rec:
            parts.append(f"First action: {first_rec}")
    elif med_count > 0:
        top_issues = ", ".join([f.get('issue') for f in top_med[:2]])
        parts.append(f"Notable issues include: {top_issues}.")
        first_rec = top_med[0].get('recommendation') if top_med and top_med[0].get('recommendation') else None
        if first_rec:
            parts.append(f"Priority fix: {first_rec}")
    elif low_count > 0:
        parts.append("Only low-severity issues were found; address them when convenient to improve security posture.")
    else:
        parts.append("No significant issues detected; maintain current best practices.")

    parts.append(f"Summary: {high_count} high, {med_count} medium, and {low_count} low issues found.")
    return " ".join(parts)


async def summarize_full_audit(audit_result: dict) -> str:
    top_issues = "\n".join([
        f"- [{i['severity']}] ({i.get('category', '')}) {i['issue']}"
        for i in audit_result.get("all_issues", [])[:10]
    ])
    cats = audit_result.get('categories', {})
    prompt = f"""
You are a professional web security consultant.
A comprehensive 7-category advanced security audit was just completed:

Overall Security Score: {audit_result.get('overall_score')}/100 (Grade: {audit_result.get('grade')})

SCORE BREAKDOWN (weighted):
- SSL/TLS Security (20% weight):       {cats.get('ssl_tls', {}).get('score', 'N/A')}/100
- Security Headers (20% weight):       {cats.get('headers', {}).get('score', 'N/A')}/100
- DNS Security (10% weight):           {cats.get('dns', {}).get('score', 'N/A')}/100
- Domain Reputation (15% weight):      {cats.get('reputation', {}).get('score', 'N/A')}/100
- Vulnerability Assessment (20% weight): {cats.get('vulns', {}).get('score', 'N/A')}/100
- Threat Intelligence (10% weight):    {cats.get('threat', {}).get('score', 'N/A')}/100
- Cookie Security (5% weight):         {cats.get('cookies', {}).get('score', 'N/A')}/100

ISSUE COUNTS:
- Critical: {audit_result.get('critical_issues', 0)}
- High: {audit_result.get('high_issues', 0)}
- Medium: {audit_result.get('medium_issues', 0)}
- Low: {audit_result.get('low_issues', 0)}
- Total: {audit_result.get('total_issues', 0)}

TOP ISSUES DETECTED:
{top_issues}

Write a 4-5 sentence professional executive summary covering:
1. Overall security verdict based on the weighted score
2. The weakest category and its impact on the business
3. Top 2 quick wins that would have the biggest impact (be specific)
4. Final recommendation

Keep it clear, actionable, and non-technical enough for a business owner to understand.
"""
    for model_name in MODEL_NAMES:
        try:
            model = genai.GenerativeModel(model_name)
            response = model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            print(f"Full audit summary error ({model_name}): {type(e).__name__}: {e}")

    score = audit_result.get('overall_score', 0)
    grade = audit_result.get('grade', 'N/A')
    crit = audit_result.get('critical_issues', 0)
    high = audit_result.get('high_issues', 0)

    if score >= 80:
        return (
            f"This website scores {score}/100 (Grade: {grade}), indicating excellent overall security posture. "
            f"There are {crit} critical and {high} high-severity issues to address for further improvement. "
            "Continue monitoring and applying recommended fixes to maintain this standard."
        )
    elif score >= 60:
        return (
            f"This website scored {score}/100 (Grade: {grade}), showing moderate security health with clear room to improve. "
            f"There are {crit} critical and {high} high-severity issues requiring prompt attention. "
            "Addressing the top issues across the 7 security categories will significantly boost the overall score."
        )
    else:
        return (
            f"This website scored {score}/100 (Grade: {grade}) — significant security improvements are needed. "
            f"There are {crit} critical issues that pose immediate risks and must be resolved urgently. "
            "A systematic review of all 7 security assessment categories is strongly recommended."
        )

