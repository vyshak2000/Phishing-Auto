import re
import os
import ipaddress
import base64
import requests
import pandas as pd
from extract_msg import Message


# ================= CONFIG =================

RAW_HEADERS_FILE = "raw_headers.txt"
MSG_FILE = "sample.msg"
OUTPUT_FILE = "analysis.xlsx"

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


# ================= IP EXTRACTION =================

def extract_public_ips_from_headers(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    found_ips = set(re.findall(ip_regex, content))

    public_ips = []

    for ip in found_ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_global:  # removes private, loopback, reserved, multicast
                public_ips.append(ip)
        except ValueError:
            pass

    return sorted(public_ips)


# ================= URL EXTRACTION =================

def extract_urls_from_msg(path):
    msg = Message(path)
    body = msg.body or ""

    url_regex = r'https?://[^\s<>"\']+'
    return sorted(set(re.findall(url_regex, body)))


# ================= VIRUSTOTAL =================

def vt_headers():
    return {"x-apikey": VT_API_KEY}


def vt_ip_reputation(ip):
    r = requests.get(
        f"{VT_BASE_URL}/ip_addresses/{ip}",
        headers=vt_headers(),
        timeout=15
    )

    if r.status_code != 200:
        return None

    return r.json()["data"]["attributes"]["last_analysis_stats"]


def vt_url_reputation(url):
    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    r = requests.get(
        f"{VT_BASE_URL}/urls/{encoded}",
        headers=vt_headers(),
        timeout=15
    )

    if r.status_code != 200:
        return None

    return r.json()["data"]["attributes"]["last_analysis_stats"]


# ================= MAIN =================

def main():
    if not VT_API_KEY:
        raise RuntimeError("VT_API_KEY environment variable not set")

    ips = extract_public_ips_from_headers(RAW_HEADERS_FILE)
    urls = extract_urls_from_msg(MSG_FILE)

    ip_results = []
    for ip in ips:
        vt = vt_ip_reputation(ip)
        ip_results.append({
            "IP Address": ip,
            "VT_Malicious": vt.get("malicious") if vt else None,
            "VT_Suspicious": vt.get("suspicious") if vt else None,
            "VT_Harmless": vt.get("harmless") if vt else None,
            "VT_Undetected": vt.get("undetected") if vt else None
        })

    url_results = []
    for url in urls:
        vt = vt_url_reputation(url)
        url_results.append({
            "URL": url,
            "VT_Malicious": vt.get("malicious") if vt else None,
            "VT_Suspicious": vt.get("suspicious") if vt else None,
            "VT_Harmless": vt.get("harmless") if vt else None,
            "VT_Undetected": vt.get("undetected") if vt else None
        })

    df_ips = pd.DataFrame(ip_results)
    df_urls = pd.DataFrame(url_results)

    with pd.ExcelWriter(OUTPUT_FILE, engine="openpyxl") as writer:
        df_ips.to_excel(writer, index=False, sheet_name="IPs")
        df_urls.to_excel(writer, index=False, sheet_name="URLs")

    print("[+] Extraction completed")
    print("[+] VirusTotal reputation added")
    print("[+] Output saved as analysis.xlsx")


if __name__ == "__main__":
    main()
