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
# SAFE HEADER EXTRACTION (SAVE TO raw_headers.txt)
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
# MULTI-LINE HEADER EXTRACTION
# ============================================================
def extract_field(raw, key):
    lines = raw.splitlines()
    result_lines = []
    capture = False

    for line in lines:
        if line.lower().startswith(key.lower() + ":"):
            capture = True
            result_lines.append(line.split(":", 1)[1].strip())
            continue
        if capture:
            if line.startswith(" ") or line.startswith("\t"):
                result_lines.append(line.strip())
            else:
                break

    return " ".join(result_lines) if result_lines else "Not Found"


# ============================================================
# PARSE IMPORTANT HEADERS
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

    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
    fields["Sender-IP"] = ips[-1] if ips else "Not Found"

    return fields


# ============================================================
# EXTRACT METADATA FROM MSG
# ============================================================
def extract_msg_metadata(msg_path):
    msg = extract_msg.Message(msg_path)
    return {
        "From": msg.sender,
        "To": msg.to,
        "Subject": msg.subject,
        "Date": msg.date,
    }


# ============================================================
# EXTRACT URLS AND ATTACHMENT HASHES
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
# COLOR CODING FUNCTIONS
# ============================================================
def color_code_header_row(cell, value):
    v = str(value).lower()

    red_terms = ["fail", "reject", "phish", "malicious", "error"]
    yellow_terms = ["softfail", "neutral", "temperror"]
    green_terms = ["pass", "clean", "none"]

    red = PatternFill(start_color="FFC7CE", fill_type="solid")
    yellow = PatternFill(start_color="FFEB9C", fill_type="solid")
    green = PatternFill(start_color="C6EFCE", fill_type="solid")

    if any(x in v for x in red_terms):
        cell.fill = red
    elif any(x in v for x in yellow_terms):
        cell.fill = yellow
    elif any(x in v for x in green_terms):
        cell.fill = green


def color_code_reputation(cell, value):
    v = str(value).lower()

    red = PatternFill(start_color="FFC7CE", fill_type="solid")
    yellow = PatternFill(start_color="FFEB9C", fill_type="solid")
    green = PatternFill(start_color="C6EFCE", fill_type="solid")

    if "m:" in v:
        mal = int(v.split("m:")[1].split()[0])
        sus = int(v.split("s:")[1].split()[0])
        if mal > 0:
            cell.fill = red
        elif sus > 0:
            cell.fill = yellow
        else:
            cell.fill = green

    elif "score:" in v:
        score = int(v.split("score:")[1].split()[0])
        if score >= 50:
            cell.fill = red
        elif score > 0:
            cell.fill = yellow
        else:
            cell.fill = green

    elif "pulses:" in v:
        pulses = int(v.split(":")[1])
        if pulses > 0:
            cell.fill = red
        else:
            cell.fill = green


# ============================================================
# CREATE EXCEL REPORT
# ============================================================
def write_excel(metadata, parsed, raw_headers, rep_urls, rep_ips, rep_hashes, output="analysis.xlsx"):

    wb = Workbook()

    # ===================== SHEET 1: HEADER ANALYSIS =====================
    ws1 = wb.active
    ws1.title = "Header Analysis"
    ws1.append(["Field", "Value"])

    for k, v in metadata.items():
        ws1.append([k, v])

    for k, v in parsed.items():
        ws1.append([k, v])
        color_code_header_row(ws1.cell(row=ws1.max_row, column=2), v)

    ws1.append([])
    ws1.append(["Raw Headers"])
    ws1.append([raw_headers])
    ws1["A" + str(ws1.max_row)].alignment = Alignment(wrapText=True)

    # ===================== SHEET 2: REPUTATION =====================
    ws2 = wb.create_sheet("Reputation")
    ws2.append(["Type", "Indicator", "VT", "AbuseIPDB", "OTX"])

    row = 2

    for url, vt, otx in rep_urls:
        ws2.append(["URL", url, vt, "N/A", otx])
        color_code_reputation(ws2.cell(row=row, column=3), vt)
        color_code_reputation(ws2.cell(row=row, column=5), otx)
        row += 1

    for ip, vt, abuse, otx in rep_ips:
        ws2.append(["IP", ip, vt, abuse, otx])
        color_code_reputation(ws2.cell(row=row, column=4), abuse)
        color_code_reputation(ws2.cell(row=row, column=5), otx)
        row += 1

    for h, vt, otx in rep_hashes:
        ws2.append(["HASH", h, vt, "N/A", otx])
        color_code_reputation(ws2.cell(row=row, column=3), vt)
        color_code_reputation(ws2.cell(row=row, column=5), otx)
        row += 1

    # ===================== SHEET 3: RAW HEADERS =====================
    ws3 = wb.create_sheet("Raw Headers")
    ws3["A1"] = raw_headers
    ws3["A1"].alignment = Alignment(wrapText=True)
    ws3.merge_cells("A1:D200")

    # ===================== FORMATTING =====================
    thin = Side(style="thin")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    header_fill = PatternFill(start_color="4B0082", fill_type="solid")
    white_font = Font(color="FFFFFF", bold=True)

    for sheet in [ws1, ws2]:
        for cell in sheet[1]:
            cell.fill = header_fill
            cell.font = white_font
            cell.border = border

        for row_cells in sheet.iter_rows(min_row=2, max_row=sheet.max_row):
            for cell in row_cells:
                cell.border = border

        for col in sheet.columns:
            max_len = max(len(str(c.value)) if c.value else 0 for c in col)
            sheet.column_dimensions[col[0].column_letter].width = max_len + 3

    wb.save(output)

    # Auto open file
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
# MAIN SCRIPT FLOW
# ============================================================
if __name__ == "__main__":
    msg_file = "sample.msg"

    api = load_api_keys()

    raw_headers = extract_raw_headers(msg_file)
    parsed_headers = parse_headers(raw_headers)
    metadata = extract_msg_metadata(msg_file)
    urls, hashes = extract_msg_indicators(msg_file)

    rep_urls = []
    for url in urls:
        vt = vt_url(api["VIRUSTOTAL_API_KEY"], url)
        otx = otx_lookup(api["OTX_API_KEY"], url)
        rep_urls.append((url, vt, otx))

    rep_ips = []
    if parsed_headers["Sender-IP"] != "Not Found":
        ip = parsed_headers["Sender-IP"]
        abuse = abuse_ip(api["ABUSEIPDB_API_KEY"], ip)
        otx = otx_lookup(api["OTX_API_KEY"], ip)
        rep_ips.append((ip, "N/A", abuse, otx))

    rep_hashes = []
    for h in hashes:
        vt = vt_hash(api["VIRUSTOTAL_API_KEY"], h)
        otx = otx_lookup(api["OTX_API_KEY"], h)
        rep_hashes.append((h, vt, otx))

    write_excel(metadata, parsed_headers, raw_headers, rep_urls, rep_ips, rep_hashes)
