import extract_msg
import hashlib
import re
import requests
import base64
from openpyxl import Workbook
from openpyxl.styles import Alignment


# ============================================================
# LOAD API KEYS
# ============================================================
def load_api_keys(path="api_keys.txt"):
    keys = {}
    with open(path, "r") as f:
        for line in f:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                keys[k] = v
    return keys


# ============================================================
# EXTRACT RAW HEADERS FROM MSG (SAFE)
# ============================================================
def extract_raw_headers(msg_path):
    msg = extract_msg.Message(msg_path)
    raw = msg.header

    if raw is None:
        raw = ""
    try:
        raw = raw if isinstance(raw, str) else str(raw)
    except:
        raw = ""

    with open("raw_headers.txt", "w", encoding="utf-8") as f:
        f.write(raw)

    return raw


# ============================================================
# HEADER MULTILINE EXTRACTION (CORRECT)
# ============================================================
def extract_field(raw, key):
    lines = raw.splitlines()
    result = []
    capture = False

    for line in lines:
        if line.lower().startswith(key.lower() + ":"):
            capture = True
            result.append(line.split(":", 1)[1].strip())
            continue

        if capture:
            if line.startswith(" ") or line.startswith("\t"):
                result.append(line.strip())
            else:
                break

    return " ".join(result) if result else "Not Found"


# ============================================================
# PARSE IMPORTANT HEADER FIELDS
# ============================================================
def parse_headers(raw):
    data = {
        "SPF": extract_field(raw, "Received-SPF"),
        "DKIM": extract_field(raw, "DKIM-Signature"),
        "DMARC": extract_field(raw, "Authentication-Results"),
        "Authentication-Results": extract_field(raw, "Authentication-Results"),
        "Return-Path": extract_field(raw, "Return-Path"),
        "Message-ID": extract_field(raw, "Message-ID"),
        "Content-Type": extract_field(raw, "Content-Type"),
        "X-Trellix": extract_field(raw, "X-Trellix"),
        "X-IronPort": extract_field(raw, "X-IronPort-Anti-Spam-Filtered"),
        "X-ThreatScanner": extract_field(raw, "X-ThreatScanner-Verdict"),
    }

    # Sender IP
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
    data["Sender-IP"] = ips[-1] if ips else "Not Found"

    return data


# ============================================================
# MSG METADATA (From, To, Subject, Date)
# ============================================================
def extract_metadata(msg_path):
    msg = extract_msg.Message(msg_path)
    return {
        "From": msg.sender,
        "To": msg.to,
        "Subject": msg.subject,
        "Date": msg.date,
    }


# ============================================================
# GET URLS + ATTACH HASHES
# ============================================================
def extract_msg_indicators(msg_path):
    msg = extract_msg.Message(msg_path)
    body = msg.body or ""

    urls = re.findall(r"https?://\S+", body)

    hashes = []
    for att in msg.attachments:
        sha = hashlib.sha256(att.data).hexdigest()
        hashes.append(sha)

    return urls, hashes


# ============================================================
# VIRUSTOTAL URL LOOKUP
# ============================================================
def vt_url(api_key, url):
    try:
        encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded}",
            headers={"x-apikey": api_key}
        )
        if r.status_code != 200:
            return f"VT URL Error {r.status_code}"
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return f"M:{stats['malicious']} S:{stats['suspicious']} H:{stats['harmless']}"
    except Exception as e:
        return f"Error: {e}"


# ============================================================
# VIRUSTOTAL HASH LOOKUP
# ============================================================
def vt_hash(api_key, sha):
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha}",
            headers={"x-apikey": api_key}
        )
        if r.status_code != 200:
            return f"VT Hash Error {r.status_code}"
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return f"M:{stats['malicious']} S:{stats['suspicious']} H:{stats['harmless']}"
    except Exception as e:
        return f"Error: {e}"


# ============================================================
# ABUSEIPDB LOOKUP
# ============================================================
def abuse_ip(api_key, ip):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 30}
        )
        if r.status_code != 200:
            return f"AbuseIPDB Error {r.status_code}"
        score = r.json()["data"]["abuseConfidenceScore"]
        return f"Score:{score}"
    except Exception as e:
        return f"Error: {e}"


# ============================================================
# OTX LOOKUP
# ============================================================
def otx_lookup(api_key, indicator):
    try:
        for t in ["IPv4", "url", "file"]:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/{t}/{indicator}/general",
                headers={"X-OTX-API-KEY": api_key}
            )
            if r.status_code == 200:
                pulses = r.json()["pulse_info"]["count"]
                return f"Pulses:{pulses}"
        return "OTX Not Found"
    except Exception as e:
        return f"Error: {e}"


# ============================================================
# WRITE EXCEL FILE
# ============================================================
def write_excel(metadata, parsed, raw_headers, rep_urls, rep_ips, rep_hashes, output="analysis.xlsx"):

    wb = Workbook()

    # ---------------- Sheet 1: Header Analysis ----------------
    ws1 = wb.active
    ws1.title = "Header Analysis"
    ws1.append(["Field", "Value"])

    for k, v in metadata.items():
        ws1.append([k, v])

    for k, v in parsed.items():
        ws1.append([k, v])

    ws1.append([])
    ws1.append(["Raw Headers"])
    ws1.append([raw_headers])
    ws1["A" + str(ws1.max_row)].alignment = Alignment(wrapText=True)

    # ---------------- Sheet 2: Reputation ----------------
    ws2 = wb.create_sheet("Reputation")
    ws2.append(["Type", "Indicator", "VT", "AbuseIPDB", "OTX"])

    for url, vt, otx in rep_urls:
        ws2.append(["URL", url, vt, "N/A", otx])

    for ip, vt, abuse, otx in rep_ips:
        ws2.append(["IP", ip, vt, abuse, otx])

    for h, vt, otx in rep_hashes:
        ws2.append(["HASH", h, vt, "N/A", otx])

    # ---------------- Sheet 3: Raw Headers File ----------------
    ws3 = wb.create_sheet("Raw Header Dump")
    ws3["A1"] = raw_headers
    ws3["A1"].alignment = Alignment(wrapText=True)
    ws3.merge_cells("A1:D200")

    wb.save(output)
    print("[+] Excel file generated:", output)


# ============================================================
# MAIN SCRIPT EXECUTION
# ============================================================
if __name__ == "__main__":

    msg_file = "sample.msg"
    api = load_api_keys()

    # Extract + parse headers
    raw_headers = extract_raw_headers(msg_file)
    parsed_headers = parse_headers(raw_headers)

    # Extract metadata
    metadata = extract_metadata(msg_file)

    # Extract URLs + hashes
    urls, hashes = extract_msg_indicators(msg_file)

    # Reputation checks
    rep_urls = []
    for url in urls:
        vt = vt_url(api["VIRUSTOTAL_API_KEY"], url)
        otx = otx_lookup(api["OTX_API_KEY"], url)
        rep_urls.append((url, vt, otx))

    rep_ips = []
    if parsed_headers["Sender-IP"] != "Not Found":
        ip = parsed_headers["Sender-IP"]
        abuse_result = abuse_ip(api["ABUSEIPDB_API_KEY"], ip)
        otx_result = otx_lookup(api["OTX_API_KEY"], ip)
        rep_ips.append((ip, "N/A", abuse_result, otx_result))

    rep_hashes = []
    for sha in hashes:
        vt = vt_hash(api["VIRUSTOTAL_API_KEY"], sha)
        otx = otx_lookup(api["OTX_API_KEY"], sha)
        rep_hashes.append((sha, vt, otx))

    write_excel(metadata, parsed_headers, raw_headers, rep_urls, rep_ips, rep_hashes)
