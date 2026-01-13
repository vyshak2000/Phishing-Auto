import extract_msg
import re
import hashlib
import requests
import base64
from openpyxl import Workbook
from openpyxl.styles import Alignment


# ============================================================
# LOAD API KEYS
# ============================================================
def load_api_keys(file_path="api_keys.txt"):
    keys = {}
    with open(file_path, "r") as f:
        for line in f:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                keys[k] = v
    return keys


# ============================================================
# READ .MSG AND EXPORT RAW HEADERS
# ============================================================
def extract_raw_headers(msg_path):
    msg = extract_msg.Message(msg_path)

    raw = msg.header

    # Force convert anything to string
    if raw is None:
        raw = ""
    try:
        raw = raw if isinstance(raw, str) else str(raw)
    except:
        raw = ""

    # Save to file
    with open("raw_headers.txt", "w", encoding="utf-8") as f:
        f.write(raw)

    return raw


# ============================================================
# MULTILINE HEADER PARSING (RFC 5322 folding support)
# ============================================================
def extract_field(raw, key):
    lines = raw.splitlines()
    result_lines = []
    capture = False

    for line in lines:
        # Start capturing when the key is found
        if line.lower().startswith(key.lower() + ":"):
            capture = True
            result_lines.append(line.split(":", 1)[1].strip())
            continue

        # Capture continuation lines (start with space or tab)
        if capture:
            if line.startswith(" ") or line.startswith("\t"):
                result_lines.append(line.strip())
            else:
                break  # stop on next header

    return " ".join(result_lines) if result_lines else "Not Found"


# ============================================================
# PARSE IMPORTANT FIELDS
# ============================================================
def parse_headers(raw):
    fields = {
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

    # Sender IP extraction
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
    fields["Sender-IP"] = ips[-1] if ips else "Not Found"

    return fields


# ============================================================
# GET URLS AND ATTACH HASHES FROM MSG BODY + ATTACHMENTS
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
# VIRUSTOTAL FILE HASH LOOKUP
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
# EXCEL OUTPUT (NO COLOR CODING)
# ============================================================
def write_excel(parsed, raw_headers, rep_urls, rep_ips, rep_hashes, output="analysis.xlsx"):
    wb = Workbook()

    # ---------------- Sheet 1: Header Analysis ----------------
    ws1 = wb.active
    ws1.title = "Header Analysis"
    ws1.append(["Field", "Value"])

    for k, v in parsed.items():
        ws1.append([k, v])

    ws1.append([])
    ws1.append(["Raw Headers"])
    ws1.append([raw_headers])
    ws1["A" + str(ws1.max_row)].alignment = Alignment(wrapText=True)

    # ---------------- Sheet 2: Reputation ----------------
    ws2 = wb.create_sheet("Reputation")
    ws2.append(["Type", "Indicator", "VT", "AbuseIPDB", "OTX"])

    row = 2

    for url, vt, otx in rep_urls:
        ws2.append(["URL", url, vt, "N/A", otx])
        row += 1

    for ip, vt, abuse, otx in rep_ips:
        ws2.append(["IP", ip, vt, abuse, otx])
        row += 1

    for h, vt, otx in rep_hashes:
        ws2.append(["HASH", h, vt, "N/A", otx])
        row += 1

    # ---------------- Sheet 3: Raw Headers ----------------
    ws3 = wb.create_sheet("Raw Header Dump")
    ws3["A1"] = raw_headers
    ws3["A1"].alignment = Alignment(wrapText=True)
    ws3.merge_cells("A1:D200")

    wb.save(output)
    print("[+] Excel file generated:", output)


# ============================================================
# MAIN EXECUTION
# ============================================================
if __name__ == "__main__":

    msg_file = "sample.msg"  # <-- Your MSG file here
    api = load_api_keys()

    raw_headers = extract_raw_headers(msg_file)
    parsed = parse_headers(raw_headers)
    urls, hashes = extract_msg_indicators(msg_file)

    # URL reputation
    rep_urls = []
    for u in urls:
        vt = vt_url(api["VIRUSTOTAL_API_KEY"], u)
        otx = otx_lookup(api["OTX_API_KEY"], u)
        rep_urls.append((u, vt, otx))

    # IP reputation
    rep_ips = []
    if parsed["Sender-IP"] != "Not Found":
        ip = parsed["Sender-IP"]
        abuse = abuse_ip(api["ABUSEIPDB_API_KEY"], ip)
        otx = otx_lookup(api["OTX_API_KEY"], ip)
        rep_ips.append((ip, "Not Supported", abuse, otx))

    # Hash reputation
    rep_hashes = []
    for h in hashes:
        vt = vt_hash(api["VIRUSTOTAL_API_KEY"], h)
        otx = otx_lookup(api["OTX_API_KEY"], h)
        rep_hashes.append((h, vt, otx))

    write_excel(parsed, raw_headers, rep_urls, rep_ips, rep_hashes)
