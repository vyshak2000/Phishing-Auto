import extract_msg
import hashlib
import re
import requests
import base64
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Border, Side, Font
import subprocess
import platform


# -------------------------
# LOAD API KEYS
# -------------------------
def load_api_keys(file_path="api_keys.txt"):
    api_keys = {}
    with open(file_path, "r") as f:
        for line in f:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                api_keys[key] = value
    return api_keys


# -------------------------
# PARSE .MSG FILE DIRECTLY
# -------------------------
def parse_msg_file(file_path):
    msg = extract_msg.Message(file_path)

    headers = {
        "From": msg.sender,
        "To": msg.to,
        "Subject": msg.subject,
        "Date": msg.date,
        "Raw-Headers": msg.header if msg.header else ""
    }

    body = msg.body

    # Extract URLs
    urls = re.findall(r"(https?://[^\s]+)", body)

    # Extract attachments
    attachments = []
    for att in msg.attachments:
        content = att.data
        sha256_hash = hashlib.sha256(content).hexdigest()
        attachments.append({
            "filename": att.longFilename,
            "sha256": sha256_hash,
            "size": len(content),
            "content": content
        })

    return headers, body, urls, attachments


# -------------------------
# VIRUSTOTAL URL LOOKUP
# -------------------------
def vt_url_lookup(api_key, url):
    try:
        encoded_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded_id}",
            headers={"x-apikey": api_key}
        )
        if r.status_code != 200:
            return {"error": f"VT URL Error {r.status_code}"}
        return r.json()["data"]["attributes"]["last_analysis_stats"]
    except Exception as e:
        return {"error": str(e)}


# -------------------------
# VIRUSTOTAL FILE HASH LOOKUP
# -------------------------
def vt_hash_lookup(api_key, sha256):
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key}
        )
        if r.status_code != 200:
            return {"error": f"VT Hash Error {r.status_code}"}
        return r.json()["data"]["attributes"]["last_analysis_stats"]
    except Exception as e:
        return {"error": str(e)}


# -------------------------
# OTX LOOKUP
# -------------------------
def otx_lookup(api_key, indicator):
    try:
        for t in ["IPv4", "url", "file"]:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/{t}/{indicator}/general",
                headers={"X-OTX-API-KEY": api_key},
            )
            if r.status_code == 200:
                return r.json()

        return {"error": "OTX Not Found"}
    except Exception as e:
        return {"error": str(e)}


# -------------------------
# ABUSEIPDB LOOKUP
# -------------------------
def abuseipdb_lookup(api_key, ip):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 30},
        )
        if r.status_code != 200:
            return {"error": f"AbuseIPDB Error {r.status_code}"}
        return r.json()["data"]
    except Exception as e:
        return {"error": str(e)}


# -------------------------
# BEAUTIFY FUNCTIONS
# -------------------------
def beautify_vt(stats):
    if "error" in stats:
        return "Error"
    return f"Malicious:{stats.get('malicious',0)} Suspicious:{stats.get('suspicious',0)} Harmless:{stats.get('harmless',0)}"


def beautify_otx(data):
    if "error" in data:
        return "Error"
    pulses = data.get("pulse_info", {}).get("count", 0)
    return f"Pulses:{pulses} Sections:{','.join(data.get('sections',[]))}"


def beautify_abuseip(data):
    if "error" in data:
        return "Error"
    return (
        f"Score:{data.get('abuseConfidenceScore',0)} "
        f"Public:{data.get('isPublic',False)} "
        f"Country:{data.get('countryCode','N/A')}"
    )


# -------------------------
# COLOR CODING
# -------------------------
def apply_color(cell, vt_text=None, abuse_text=None):
    red = PatternFill(start_color="FFC7CE", fill_type="solid")
    yellow = PatternFill(start_color="FFEB9C", fill_type="solid")
    green = PatternFill(start_color="C6EFCE", fill_type="solid")

    if vt_text and "Error" not in vt_text:
        mal = int(vt_text.split("Malicious:")[1].split()[0])
        sus = int(vt_text.split("Suspicious:")[1].split()[0])
        if mal > 0:
            cell.fill = red
        elif sus > 0:
            cell.fill = yellow
        else:
            cell.fill = green

    if abuse_text and "Error" not in abuse_text:
        score = int(abuse_text.split("Score:")[1].split()[0])
        if score > 50:
            cell.fill = red
        elif score > 0:
            cell.fill = yellow
        else:
            cell.fill = green


# -------------------------
# MULTITHREAD WRAPPER
# -------------------------
def parallel_execute(func, items, *args):
    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_map = {executor.submit(func, *args, item): item for item in items}
        for future in as_completed(future_map):
            indicator = future_map[future]
            try:
                results.append((indicator, future.result()))
            except Exception as e:
                results.append((indicator, {"error": str(e)}))
    return results


# -------------------------
# WRITE TO EXCEL + STYLING + OPEN FILE
# -------------------------
def write_to_excel(headers, url_results, ip_result, attachment_results, output="email_report.xlsx"):

    wb = Workbook()

    # -------------------------
    # HEADERS SHEET
    # -------------------------
    ws1 = wb.active
    ws1.title = "Headers"
    ws1.append(["Field", "Value"])

    for k, v in headers.items():
        ws1.append([k, v])

    # -------------------------
    # REPUTATION SHEET
    # -------------------------
    ws2 = wb.create_sheet("Reputation")
    ws2.append(["Type", "Indicator", "VirusTotal", "AbuseIPDB", "OTX"])

    row = 2

    # URL results
    for url, vt, otx in url_results:
        vt_text = beautify_vt(vt)
        otx_text = beautify_otx(otx)
        ws2.append(["URL", url, vt_text, "N/A", otx_text])
        apply_color(ws2[f"C{row}"], vt_text, None)
        row += 1

    # IP result
    if ip_result:
        ip, vt_ip, abuse, otx_ip = ip_result
        vt_text = beautify_vt(vt_ip)
        abuse_text = beautify_abuseip(abuse)
        otx_text = beautify_otx(otx_ip)

        ws2.append(["IP", ip, vt_text, abuse_text, otx_text])
        apply_color(ws2[f"C{row}"], vt_text, None)
        apply_color(ws2[f"D{row}"], None, abuse_text)
        row += 1

    # Attachments
    for sha, vt, otx in attachment_results:
        vt_text = beautify_vt(vt)
        otx_text = beautify_otx(otx)
        ws2.append(["Attachment", sha, vt_text, "N/A", otx_text])
        apply_color(ws2[f"C{row}"], vt_text, None)
        row += 1

    # -------------------------
    # ADD BORDERS + HEADER STYLE
    # -------------------------
    thin = Side(style="thin")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    header_fill = PatternFill(start_color="4B0082", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF")

    for sheet in [ws1, ws2]:
        for cell in sheet[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.border = border

        for row_cells in sheet.iter_rows(min_row=2, max_row=sheet.max_row, max_col=sheet.max_column):
            for cell in row_cells:
                cell.border = border

    # Auto column width
    for sheet in [ws1, ws2]:
        for col in sheet.columns:
            max_len = max(len(str(c.value)) if c.value else 0 for c in col)
            sheet.column_dimensions[col[0].column_letter].width = max_len + 3

    wb.save(output)
    print(f"Excel file generated: {output}")

    # -------------------------
    # AUTO-OPEN FILE
    # -------------------------
    if platform.system() == "Windows":
        os.startfile(output)
    elif platform.system() == "Darwin":
        subprocess.call(["open", output])
    else:
        subprocess.call(["xdg-open", output])


# -------------------------
# MAIN EXECUTION
# -------------------------
if __name__ == "__main__":

    input_file = "sample.msg"   # CHANGE THIS

    api = load_api_keys()

    headers, body, urls, attachments = parse_msg_file(input_file)

    # URL intel
    vt_url_res = parallel_execute(vt_url_lookup, urls, api["VIRUSTOTAL_API_KEY"])
    otx_url_res = parallel_execute(otx_lookup, urls, api["OTX_API_KEY"])
    url_results = [(u, vt, otx) for (u, vt), (_, otx) in zip(vt_url_res, otx_url_res)]

    # Extract IP (if any) from raw headers
    raw = headers.get("Raw-Headers", "")
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", raw)
    ip_result = None

    if match:
        ip = match.group(0)
        vt = vt_url_lookup(api["VIRUSTOTAL_API_KEY"], ip)  # will error for IP → we skip
        abuse = abuseipdb_lookup(api["ABUSEIPDB_API_KEY"], ip)
        otx = otx_lookup(api["OTX_API_KEY"], ip)
        vt_ip = vt_hash_lookup(api["VIRUSTOTAL_API_KEY"], ip) if False else {"error": "VT does not support IP here"}
        ip_result = (ip, vt_ip, abuse, otx)

    # Attachments
    hashes = [a["sha256"] for a in attachments]
    vt_att = parallel_execute(vt_hash_lookup, hashes, api["VIRUSTOTAL_API_KEY"])
    otx_att = parallel_execute(otx_lookup, hashes, api["OTX_API_KEY"])
    attachment_results = [(sha, vt, otx) for (sha, vt), (_, otx) in zip(vt_att, otx_att)]

    # Excel export
    write_to_excel(headers, url_results, ip_result, attachment_results)
