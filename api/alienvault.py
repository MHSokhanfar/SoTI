"""AlienVault OTX API v1 - supports IP, domain and file hash.

Created and developed by Mohammad Hossein Sokhanfar.
Repository: https://github.com/MHSokhanfar/SoTI
"""
import ipaddress

from api import fetch, make_result, missing_key
from config import settings

NAME = "AlienVault OTX"
BASE = "https://otx.alienvault.com/api/v1/indicators"


def _path(indicator: str, itype: str) -> str:
    if itype == "ip":
        ver = ipaddress.ip_address(indicator).version
        return f"IPv{ver}/{indicator}"
    return f"{'domain' if itype == 'domain' else 'file'}/{indicator}"


def parse_response(indicator: str, itype: str, data: dict) -> dict:
    pulse_info = data.get("pulse_info", {})
    pulses = pulse_info.get("count", 0)

    if pulses >= 5:
        verdict = "Malicious"
    elif pulses >= 1:
        verdict = "Suspicious"
    else:
        verdict = "Unknown"  # absence from OTX does not mean clean

    details = {"Pulses": pulses}
    names = [p.get("name") for p in pulse_info.get("pulses", [])[:3] if p.get("name")]
    if names:
        details["Top Pulses"] = " | ".join(names)

    families = sorted({
        f.get("display_name") or f.get("id")
        for p in pulse_info.get("pulses", [])
        for f in p.get("malware_families", [])
        if isinstance(f, dict)
    } - {None})
    if families:
        details["Malware Families"] = ", ".join(families[:6])

    if itype == "ip":
        details.update({
            "Country": data.get("country_name", "N/A"),
            "ASN": data.get("asn", "N/A"),
            "Reputation": data.get("reputation", "N/A"),
        })
    elif itype == "domain":
        details["Alexa"] = data.get("alexa", "N/A")
        details["Whois"] = data.get("whois", "N/A")
    else:
        details["Type"] = data.get("type_title", "N/A")

    gui = {"ip": "ip", "domain": "domain", "hash": "file"}[itype]
    return make_result(
        NAME, indicator, itype, "ok", verdict,
        score=f"{pulses} pulses",
        summary=f"Found in {pulses} OTX pulse(s)",
        details=details,
        link=f"https://otx.alienvault.com/indicator/{gui}/{indicator}",
    )


def lookup(indicator: str, itype: str) -> dict:
    if not settings.OTX_API_KEY:
        return missing_key(NAME, indicator, itype, "OTX_API_KEY")

    data, err = fetch(
        NAME, indicator, itype,
        f"{BASE}/{_path(indicator, itype)}/general",
        headers={"X-OTX-API-KEY": settings.OTX_API_KEY},
    )
    if err:
        return err

    return parse_response(indicator, itype, data)
