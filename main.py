import extract_msg
import re
import hashlib
import requests
import base64
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Border, Side, Font, Alignment
import platform
import subprocess


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

    # Force convert anything to string (Message object safe)
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
# PARSE RAW HEADERS INTO KEY FIELDS
# ============================================================
def extract_field(raw, key):
    for line in raw.splitlines():
        if line.lower().startswith(key.lower()):
            return line.split(":", 1)[1].strip()
    return "Not Found"


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
        "X-ThreatScanner": extract_field(raw, "X-ThreatScanner-Verdict")
    }

    # Extract sender IP
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
    fields["Sender-IP"] = ips[-1] if ips else "Not Found"

    return fields


# ============================================================
# EXTRACT URLs, ATTACHMENTS, IP FROM .MSG FILE
# ============================================================
def extract_msg_indicators(msg_path):
    msg = extract_msg.Message(msg_path)
    body = msg.body or ""

    urls = re.findall(r"https?://\S+", body)

    attachments = []
    for att in msg.attachments:
        sha = hashlib.sha256(att.data).hexdigest()
        attachments.append(sha)

    return urls, attachments


# ============================================================
# REPUTATION LOOKUPS
# ============================================================
def vt_url(api_key, url):
    try:
        encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded}",
                         headers={"x-apikey": api_key})
        if r.status_code != 200:
            return f"VT URL Error {r.status_code}"
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return f"M:{stats['malicious']} S:{stats['suspicious']} H:{stats['harmless']}"
    except Exception as e:
        return f"Error: {e}"


def vt_hash(api_key, sha):
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha}",
                         headers={"x-apikey": api_key})
        if r.status_code != 200:
            return f"VT Hash Error {r.status_code}"
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return f"M:{stats['malicious']} S:{stats['suspicious']} H:{stats['harmless']}"
    except Exception as e:
        return f"Error: {e}"


def abuse_ip(api_key, ip):
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": api_key, "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": 30})
        if r.status_code != 200:
            return f"AbuseIPDB Error {r.status_code}"
        data = r.json()["data"]
        return f"Score:{data['abuseConfidenceScore']} ISP:{data.get('isp')}"
    except Exception as e:
        return f"Error: {e}"


def otx_lookup(api_key, indicator):
    try:
        for t in ["IPv4", "url", "file"]:
            r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/{t}/{indicator}/general",
                             headers={"X-OTX-API-KEY": api_key})
            if r.status_code == 200:
                pulses = r.json()["pulse_info"]["count"]
                return f"Pulses:{pulses}"
        return "OTX Not Found"
    except Exception as e:
        return f"Error: {e}"


# ============================================================
# MULTITHREAD UTILITY
# ============================================================
def run_parallel(func, items, *args):
    results = []
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(func, *args, item): item for item in items}
        for future in as_completed(futures):
            ind = futures[future]
            try:
                results.append((ind, future.result()))
            except Exception as e:
                results.append((ind, f"Error: {e}"))
    return results


# ============================================================
# EXCEL OUTPUT
# ============================================================
def write_excel(parsed, raw_headers, rep_urls, rep_ips, rep_hashes, output="analysis.xlsx"):
    wb = Workbook()

    # ---------------- Sheet 1 : Header Analysis ----------------
    ws1 = wb.active
    ws1.title = "Header Analysis"
    ws1.append(["Field", "Value"])

    for k, v in parsed.items():
        ws1.append([k, v])

    ws1.append([])
    ws1.append(["Raw Headers"])
    ws1.append([raw_headers])

    # ---------------- Sheet 2 : Reputation ----------------
    ws2 = wb.create_sheet("Reputation")
    ws2.append(["Type", "Indicator", "VT", "AbuseIPDB", "OTX"])

    row = 2
    # URLs
    for url, vt, otx in rep_urls:
        ws2.append(["URL", url, vt, "N/A", otx])
        row += 1

    # IP
    for ip, vt, abuse, otx in rep_ips:
        ws2.append(["IP", ip, vt, abuse, otx])
        row += 1

    # HASHES
    for h, vt, otx in rep_hashes:
        ws2.append(["HASH", h, vt, "N/A", otx])
        row += 1

    # ---------------- Formatting ----------------
    thin = Side(style="thin")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    header_fill = PatternFill(start_color="4B0082", fill_type="solid")
    white_font = Font(color="FFFFFF", bold=True)

    for sheet in [ws1, ws2]:
        for cell in sheet[1]:
            cell.fill = header_fill
            cell.font = white_font
            cell.border = border

        for r in sheet.iter_rows(min_row=2):
            for c in r:
                c.border = border

        # Auto column width
        for column in sheet.columns:
            max_len = max(len(str(cell.value)) if cell.value else 0 for cell in column)
            sheet.column_dimensions[column[0].column_letter].width = max_len + 3

    wb.save(output)

    # Auto-open
    try:
        if platform.system() == "Windows":
            os.startfile(output)
        elif platform.system() == "Darwin":
            subprocess.call(["open", output])
        else:
            subprocess.call(["xdg-open", output])
    except:
        pass


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    msg_file = "sample.msg"  # CHANGE THIS

    api = load_api_keys()

    # 1. Extract raw headers
    raw_headers = extract_raw_headers(msg_file)

    # 2. Parse important fields
    parsed = parse_headers(raw_headers)

    # 3. Extract URLs + Attachment hashes
    urls, hashes = extract_msg_indicators(msg_file)

    # 4. Reputation checks
    rep_urls = []
    for url in urls:
        vt = vt_url(api["VIRUSTOTAL_API_KEY"], url)
        otx = otx_lookup(api["OTX_API_KEY"], url)
        rep_urls.append((url, vt, otx))

    rep_ips = []
    if parsed["Sender-IP"] != "Not Found":
        ip = parsed["Sender-IP"]
        vt = "Not Supported"
        abuse = abuse_ip(api["ABUSEIPDB_API_KEY"], ip)
        otx = otx_lookup(api["OTX_API_KEY"], ip)
        rep_ips.append((ip, vt, abuse, otx))

    rep_hashes = []
    for h in hashes:
        vt = vt_hash(api["VIRUSTOTAL_API_KEY"], h)
        otx = otx_lookup(api["OTX_API_KEY"], h)
        rep_hashes.append((h, vt, otx))

    # 5. Write Excel
    write_excel(parsed, raw_headers, rep_urls, rep_ips, rep_hashes)
