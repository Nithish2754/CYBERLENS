import re

def extract_urls_from_email(text: str) -> list:
    """Extract all URLs from email text."""
    return list(set(re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)))

def extract_email_metadata(text: str) -> dict:
    """Extract sender, subject, and other metadata from email."""
    sender = re.search(r'From:\s*(.+)', text, re.IGNORECASE)
    subject = re.search(r'Subject:\s*(.+)', text, re.IGNORECASE)
    reply_to = re.search(r'Reply-To:\s*(.+)', text, re.IGNORECASE)
    
    return {
        "sender": sender.group(1).strip() if sender else "Unknown",
        "subject": subject.group(1).strip() if subject else "Unknown",
        "reply_to": reply_to.group(1).strip() if reply_to else None,
        "url_count": len(extract_urls_from_email(text)),
        "word_count": len(text.split())
    }
