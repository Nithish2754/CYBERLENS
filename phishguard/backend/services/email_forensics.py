import re


def analyze_email_headers(email_text: str) -> dict:
    flags = []
    score = 0

    # Extract all headers
    from_header = re.search(r'From:\s*(.+)', email_text, re.IGNORECASE)
    reply_to = re.search(r'Reply-To:\s*(.+)', email_text, re.IGNORECASE)
    return_path = re.search(r'Return-Path:\s*(.+)', email_text, re.IGNORECASE)
    received = re.findall(r'Received:\s*(.+)', email_text, re.IGNORECASE)
    message_id = re.search(r'Message-ID:\s*(.+)', email_text, re.IGNORECASE)
    spf = re.search(r'spf=(pass|fail|softfail|neutral)', email_text, re.IGNORECASE)
    dkim = re.search(r'dkim=(pass|fail)', email_text, re.IGNORECASE)
    dmarc = re.search(r'dmarc=(pass|fail)', email_text, re.IGNORECASE)

    # SPF/DKIM/DMARC checks
    if spf and spf.group(1).lower() in ['fail', 'softfail']:
        flags.append(f"SPF authentication FAILED — sender not authorized")
        score += 45

    if dkim and dkim.group(1).lower() == 'fail':
        flags.append("DKIM signature verification FAILED — email may be forged")
        score += 40

    if dmarc and dmarc.group(1).lower() == 'fail':
        flags.append("DMARC policy check FAILED — likely spoofed sender")
        score += 50

    # From vs Reply-To mismatch
    if from_header and reply_to:
        from_email = re.search(r'[\w.-]+@[\w.-]+', from_header.group(1))
        reply_email = re.search(r'[\w.-]+@[\w.-]+', reply_to.group(1))
        if from_email and reply_email:
            from_domain = from_email.group().split('@')[1]
            reply_domain = reply_email.group().split('@')[1]
            if from_domain != reply_domain:
                flags.append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})")
                score += 35

    # From vs Return-Path mismatch
    if from_header and return_path:
        from_email = re.search(r'[\w.-]+@[\w.-]+', from_header.group(1))
        return_email = re.search(r'[\w.-]+@[\w.-]+', return_path.group(1))
        if from_email and return_email:
            if from_email.group().split('@')[1] != return_email.group().split('@')[1]:
                flags.append("Return-Path domain differs from sender — email routing anomaly")
                score += 25

    # Suspicious Message-ID
    if message_id:
        mid = message_id.group(1)
        if not re.search(r'@[\w.-]+\.\w+', mid):
            flags.append("Malformed Message-ID — may indicate spoofed email")
            score += 20

    # Multiple received hops from suspicious countries
    suspicious_country_codes = ['.ru', '.cn', '.ua', '.ro', '.br']
    for received_line in received:
        for code in suspicious_country_codes:
            if code in received_line.lower():
                flags.append(f"Email routed through suspicious geographic region")
                score += 20
                break

    # Display name spoofing
    if from_header:
        from_str = from_header.group(1)
        display_match = re.search(r'"?([^"<]+)"?\s*<(.+)>', from_str)
        if display_match:
            display_name = display_match.group(1).lower().strip()
            email_addr = display_match.group(2).lower()
            brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple',
                     'facebook', 'netflix', 'bank', 'chase', 'support', 'security']
            for brand in brands:
                if brand in display_name and brand not in email_addr:
                    flags.append(f"Display name claims to be '{brand.title()}' but email address doesn't match")
                    score += 50
                    break

    return {
        "spf": spf.group(1) if spf else "not found",
        "dkim": dkim.group(1) if dkim else "not found",
        "dmarc": dmarc.group(1) if dmarc else "not found",
        "flags": flags,
        "header_score": min(100, score)
    }
