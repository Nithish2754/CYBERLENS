"""
compliance_service.py
Maps security findings → compliance framework requirements.
Key fixes vs previous version:
  - Severity-weighted scoring (CRITICAL -18, HIGH -10, MEDIUM -5, LOW -2)
  - 30-point minimum floor; score capped so no framework hits 0 for real sites
  - Baseline credit from passed checks (up to +20)
  - Selective mapping: each finding maps to at most 2 frameworks
  - Full issue objects stored so the frontend can show real fix text + severity
"""

from typing import List, Dict


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

SEVERITY_DEDUCTIONS = {
    "CRITICAL": 18,
    "HIGH":     10,
    "MEDIUM":    5,
    "LOW":       2,
    "INFO":      1,
}


def calculate_fw_score(findings: list, passed_count: int = 0) -> int:
    """
    Severity-weighted score with a minimum floor of 30.
    findings: list of issue dicts (must have 'severity' key)
    passed_count: number of passed checks to award baseline credit
    """
    deductions = 0
    for issue in findings:
        sev = issue.get("severity", "LOW") if isinstance(issue, dict) else "LOW"
        deductions += SEVERITY_DEDUCTIONS.get(sev, 2)

    # Baseline credit — capped at 20 points
    baseline_credit = min(20, passed_count * 2)

    raw = 100 - min(70, deductions) + baseline_credit
    return max(30, min(100, raw))


def _issue_obj(issue: dict) -> dict:
    """Return a trimmed issue object safe for JSON serialisation."""
    return {
        "issue":    issue.get("issue", ""),
        "fix":      issue.get("fix", ""),
        "severity": issue.get("severity", "MEDIUM"),
        "category": issue.get("category", ""),
        "standard": issue.get("standard", ""),
    }


# ---------------------------------------------------------------------------
# Main mapping function
# ---------------------------------------------------------------------------

def map_to_compliance_frameworks(all_issues: list, all_passed: list = None) -> dict:
    """
    Maps detected security issues to compliance framework requirements.
    No new API calls — purely maps existing findings to frameworks.
    Each finding is mapped to at most 2 frameworks to avoid double-counting.
    """
    passed_count = len(all_passed) if all_passed else 0

    frameworks: Dict[str, dict] = {
        "NIST_CSF": {
            "name": "NIST Cybersecurity Framework",
            "version": "v1.1",
            "categories": {
                "ID.RA (Risk Assessment)":    [],
                "PR.DS (Data Security)":      [],
                "PR.IP (Info Protection)":    [],
                "DE.CM (Security Monitoring)": [],
                "RS.MI (Mitigation)":         [],
            },
            "findings": [],
        },
        "GDPR": {
            "name": "GDPR Security Requirements",
            "version": "EU 2016/679",
            "articles": {
                "Art.25 — Data Protection by Design": [],
                "Art.32 — Security of Processing":    [],
                "Art.33 — Breach Notification":       [],
                "Art.35 — Data Protection Impact":    [],
            },
            "findings": [],
        },
        "PCI_DSS": {
            "name": "PCI-DSS Requirements",
            "version": "v4.0",
            "requirements": {
                "Req 2 — Secure Configurations": [],
                "Req 4 — Encryption in Transit": [],
                "Req 6 — Secure Systems":        [],
                "Req 8 — Authentication":        [],
            },
            "findings": [],
        },
        "ISO_27001": {
            "name": "ISO/IEC 27001",
            "version": "2022",
            "controls": {
                "A.8.9  — Configuration Management": [],
                "A.8.20 — Network Security":         [],
                "A.8.24 — Cryptography":             [],
                "A.8.28 — Secure Coding":            [],
            },
            "findings": [],
        },
        "CIS_CONTROLS": {
            "name": "CIS Controls",
            "version": "v8",
            "controls": {
                "CIS 3  — Data Protection":      [],
                "CIS 4  — Secure Configuration": [],
                "CIS 9  — Email/Browser Protection": [],
                "CIS 16 — Application Security": [],
            },
            "findings": [],
        },
    }

    # ------------------------------------------------------------------
    # Selective mapping: each finding → at most 2 frameworks
    # Priority rules determine which frameworks are most relevant.
    # ------------------------------------------------------------------
    for issue in all_issues:
        category  = issue.get("category", "")
        issue_txt = issue.get("issue", "").lower()
        obj       = _issue_obj(issue)

        mapped: List[str] = []  # frameworks already mapped for this issue

        # ── SSL / TLS ── primary: PCI_DSS, secondary: ISO_27001
        if category == "SSL/TLS":
            frameworks["PCI_DSS"]["requirements"]["Req 4 — Encryption in Transit"].append(obj)
            frameworks["PCI_DSS"]["findings"].append(obj)
            mapped.append("PCI_DSS")

            frameworks["ISO_27001"]["controls"]["A.8.24 — Cryptography"].append(obj)
            frameworks["ISO_27001"]["findings"].append(obj)
            mapped.append("ISO_27001")

        # ── Security Headers ── primary: NIST_CSF, secondary: CIS_CONTROLS
        elif category == "Security Headers":
            frameworks["NIST_CSF"]["categories"]["PR.DS (Data Security)"].append(obj)
            frameworks["NIST_CSF"]["findings"].append(obj)
            mapped.append("NIST_CSF")

            frameworks["CIS_CONTROLS"]["controls"]["CIS 4  — Secure Configuration"].append(obj)
            frameworks["CIS_CONTROLS"]["findings"].append(obj)
            mapped.append("CIS_CONTROLS")

        # ── Cookie Security ── primary: GDPR, secondary: PCI_DSS
        elif category == "Cookie Security":
            frameworks["GDPR"]["articles"]["Art.32 — Security of Processing"].append(obj)
            frameworks["GDPR"]["findings"].append(obj)
            mapped.append("GDPR")

            if "PCI_DSS" not in mapped:
                frameworks["PCI_DSS"]["requirements"]["Req 8 — Authentication"].append(obj)
                frameworks["PCI_DSS"]["findings"].append(obj)
                mapped.append("PCI_DSS")

        # ── DNS Security ── primary: NIST_CSF, secondary: ISO_27001
        elif category == "DNS Security":
            frameworks["NIST_CSF"]["categories"]["PR.IP (Info Protection)"].append(obj)
            frameworks["NIST_CSF"]["findings"].append(obj)
            mapped.append("NIST_CSF")

            frameworks["ISO_27001"]["controls"]["A.8.20 — Network Security"].append(obj)
            frameworks["ISO_27001"]["findings"].append(obj)
            mapped.append("ISO_27001")

        # ── Vulnerability / CVE ── primary: CIS_CONTROLS, secondary: ISO_27001
        elif category in ("Vulnerability", "CVE"):
            frameworks["CIS_CONTROLS"]["controls"]["CIS 16 — Application Security"].append(obj)
            frameworks["CIS_CONTROLS"]["findings"].append(obj)
            mapped.append("CIS_CONTROLS")

            frameworks["ISO_27001"]["controls"]["A.8.28 — Secure Coding"].append(obj)
            frameworks["ISO_27001"]["findings"].append(obj)
            mapped.append("ISO_27001")

        # ── Threat Intelligence ── NIST_CSF only
        elif category == "Threat Intelligence":
            frameworks["NIST_CSF"]["categories"]["DE.CM (Security Monitoring)"].append(obj)
            frameworks["NIST_CSF"]["findings"].append(obj)
            mapped.append("NIST_CSF")

        # ── Domain Reputation ── NIST_CSF only
        elif category == "Domain Reputation":
            frameworks["NIST_CSF"]["categories"]["ID.RA (Risk Assessment)"].append(obj)
            frameworks["NIST_CSF"]["findings"].append(obj)
            mapped.append("NIST_CSF")

        # ── Data / Privacy keywords that didn't match above → GDPR
        if "GDPR" not in mapped:
            if ("cookie" in issue_txt or "privacy" in issue_txt or
                    "personal data" in issue_txt or "consent" in issue_txt):
                frameworks["GDPR"]["articles"]["Art.25 — Data Protection by Design"].append(obj)
                frameworks["GDPR"]["findings"].append(obj)
                mapped.append("GDPR")

    # ------------------------------------------------------------------
    # Score each framework
    # ------------------------------------------------------------------
    compliance_scores: Dict[str, dict] = {}
    for fw_key, fw_data in frameworks.items():
        findings = fw_data["findings"]
        fw_score = calculate_fw_score(findings, passed_count)
        non_compliant = len(findings)

        grade = (
            "A+" if fw_score >= 95 else
            "A"  if fw_score >= 85 else
            "B"  if fw_score >= 70 else
            "C"  if fw_score >= 55 else
            "D"  if fw_score >= 40 else
            "F"
        )

        # Derive status from score — aligned with frontend thresholds
        status = (
            "COMPLIANT"     if fw_score >= 70 else
            "PARTIAL"       if fw_score >= 40 else
            "NON-COMPLIANT"
        )

        compliance_scores[fw_key] = {
            "name":                 fw_data["name"],
            "score":                fw_score,
            "grade":                grade,
            "status":               status,
            "non_compliant_findings": non_compliant,
            "details":              fw_data,
        }

    overall_compliance = (
        round(sum(v["score"] for v in compliance_scores.values()) / len(compliance_scores))
        if compliance_scores else 100
    )

    return {
        "overall_compliance_score": overall_compliance,
        "frameworks":               compliance_scores,
        "summary":                  generate_compliance_summary(compliance_scores),
    }


def generate_compliance_summary(compliance_scores: dict) -> list:
    summary = []
    for fw_key, fw_data in compliance_scores.items():
        summary.append({
            "framework":              fw_data["name"],
            "score":                  fw_data["score"],
            "grade":                  fw_data["grade"],
            "status":                 fw_data["status"],
            "non_compliant_findings": fw_data["non_compliant_findings"],
        })
    return summary
