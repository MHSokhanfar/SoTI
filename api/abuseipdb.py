"""AbuseIPDB API v2 - supports IP addresses only.

Created and developed by Mohammad Hossein Sokhanfar.
Repository: https://github.com/MHSokhanfar/SoTI
"""
from api import fetch, make_result, missing_key, unsupported
from config import settings

NAME = "AbuseIPDB"
URL = "https://api.abuseipdb.com/api/v2/check"


def parse_response(indicator: str, itype: str, data: dict) -> dict:
    d = data.get("data", {})
    score = d.get("abuseConfidenceScore", 0)
    reports = d.get("totalReports", 0)

    if score >= 75:
        verdict = "Malicious"
    elif score >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    details = {
        "Abuse Confidence": f"{score}%",
        "Total Reports": reports,
        "Distinct Reporters": d.get("numDistinctUsers", 0),
        "Last Reported": d.get("lastReportedAt") or "Never",
        "Country": d.get("countryCode", "N/A"),
        "ISP": d.get("isp", "N/A"),
        "Usage Type": d.get("usageType", "N/A"),
        "Domain": d.get("domain", "N/A"),
        "Whitelisted": d.get("isWhitelisted"),
        "Tor": d.get("isTor"),
    }
    return make_result(
        NAME, indicator, itype, "ok", verdict,
        score=f"{score}%",
        summary=f"{reports} reports in last {settings.ABUSEIPDB_MAX_AGE_DAYS} days",
        details=details,
        link=f"https://www.abuseipdb.com/check/{indicator}",
    )


def lookup(indicator: str, itype: str) -> dict:
    if itype != "ip":
        return unsupported(NAME, indicator, itype, itype)
    if not settings.ABUSEIPDB_API_KEY:
        return missing_key(NAME, indicator, itype, "ABUSEIPDB_API_KEY")

    data, err = fetch(
        NAME, indicator, itype, URL,
        headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": indicator,
                "maxAgeInDays": settings.ABUSEIPDB_MAX_AGE_DAYS},
    )
    if err:
        return err

    return parse_response(indicator, itype, data)
