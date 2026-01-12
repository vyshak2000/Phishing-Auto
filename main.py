import email
from email import policy
from email.parser import BytesParser
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Border, Side, Font
import hashlib
import requests
import re
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed


# -------------------------------------
# LOAD API KEYS
# -------------------------------------
def load_api_keys(file_path="api_keys.txt"):
    api_keys = {}
    with open(file_path, "r") as f:
        for line in f:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                api_keys[key] = value
    return api_keys


# -------------------------------------
# PARSE EMAIL HEADERS
# -------------------------------------
def parse_email_headers(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = {
        "From": msg.get("From"),
        "To": msg.get("To"),
        "Subject": msg.get("Subject"),
        "Return-Path": msg.get("Return-Path"),
        "Reply-To": msg.get("Reply-To"),
        "Received": msg.get_all("Received"),
        "Received-SPF": msg.get("Received-SPF"),
        "Authentication-Results": msg.get("Authentication-Results"),
        "DKIM-Signature": msg.get("DKIM-Signature"),
        "Message-ID": msg.get("Message-ID"),
        "Date": msg.get("Date"),
    }

    return msg, headers


# -------------------------------------
# URL & ATTACHMENT EXTRACTION
# -------------------------------------
def extract_urls_and_attachments(msg):
    urls = []
    attachments = []

    # extract URLs
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body = part.get_payload(decode=True).decode(errors="ignore")
                    urls.extend(re.findall(r"(https?://[^\s]+)", body))
                except:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode(errors="ignore")
            urls.extend(re.findall(r"(https?://[^\s]+)", body))
        except:
            pass

    # extract attachments
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            content = part.get_payload(decode=True)
            sha256_hash = hashlib.sha256(content).hexdigest()
            attachments.append({
                "filename": part.get_filename(),
                "sha256": sha256_hash,
                "size": len(content)
            })

    return urls, attachments


# -------------------------------------
# VIRUSTOTAL URL LOOKUP
# -------------------------------------
def vt_url_lookup(api_key, url):
    try:
        headers = {"x-apikey": api_key}

        encoded_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded_id}",
            headers=headers
        )

        if r.status_code != 200:
            return {"error": f"VT URL Error {r.status_code}"}

        return r.json()["data"]["attributes"]["last_analysis_stats"]

    except Exception as e:
        return {"error": str(e)}


# -------------------------------------
# VIRUSTOTAL FILE HASH LOOKUP
# -------------------------------------
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


# -------------------------------------
# VIRUSTOTAL IP LOOKUP
# -------------------------------------
def vt_ip_lookup(api_key, ip):
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key}
        )
        if r.status_code != 200:
            return {"error": f"VT IP Error {r.status_code}"}
        return r.json()["data"]["attributes"]["last_analysis_stats"]

    except Exception as e:
        return {"error": str(e)}


# -------------------------------------
# ABUSEIPDB LOOKUP
# -------------------------------------
def abuseipdb_lookup(api_key, ip):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "30"}
        )
        if r.status_code != 200:
            return {"error": f"AbuseIPDB Error {r.status_code}"}
        return r.json()["data"]
    except Exception as e:
        return {"error": str(e)}


# -------------------------------------
# OTX LOOKUP
# -------------------------------------
def otx_lookup(api_key, indicator):
    try:
        for t in ["IPv4", "url", "file"]:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/{t}/{indicator}/general",
                headers={"X-OTX-API-KEY": api_key}
            )
            if r.status_code == 200:
                return r.json()
        return {"error": "OTX Not Found"}

    except Exception as e:
        return {"error": str(e)}


# -------------------------------------
# BEAUTIFY RESULTS
# -------------------------------------
def beautify_vt(stats):
    if "error" in stats:
        return "Error"
    return (
        f"Malicious:{stats.get('malicious',0)} "
        f"Suspicious:{stats.get('suspicious',0)} "
        f"Harmless:{stats.get('harmless',0)}"
    )


def beautify_vt_ip(stats):
    if "error" in stats:
        return "Error"
    return (
        f"Malicious:{stats.get('malicious',0)} "
        f"Suspicious:{stats.get('suspicious',0)} "
        f"Harmless:{stats.get('harmless',0)}"
    )


def beautify_abuseip(data):
    if "error" in data:
        return "Error"
    return (
        f"Score:{data.get('abuseConfidenceScore',0)} "
        f"Public:{data.get('isPublic',False)} "
        f"Whitelist:{data.get('isWhitelisted',False)} "
        f"Country:{data.get('countryCode','N/A')} "
        f"Usage:{data.get('usageType','N/A')} "
        f"ISP:{data.get('isp', 'N/A')} "
        f"Hostnames:{data.get('hostnames', 'N/A')} "
        f"Is Tor Server:{data.get('isTor', 'N/A')} "
    )


def beautify_otx_url(data):
    if "error" in data:
        return "Error"
    pulses = data.get("pulse_info", {}).get("count", 0)
    validation = [v.get("message", "") for v in data.get("validation", [])] or ["None"]
    false_pos = data.get("false_positive", []) or ["None"]
    general_keys = ", ".join(data.get("general", {}).keys())
    http_count = len(data.get("http_scans", []))
    return (
        f"Pulses:{pulses} "
        f"Validation:{','.join(validation)} "
        f"FalsePos:{','.join(false_pos)} "
        f"General:{general_keys} "
        f"HTTPScans:{http_count}"
    )


def beautify_otx_ip(data):
    if "error" in data:
        return "Error"
    return (
        f"Reputation:{data.get('reputation',0)} "
        f"Pulses:{data.get('pulse_info',{}).get('count',0)} "
        f"ASN:{data.get('asn','N/A')} "
        f"Country:{data.get('country_name','N/A')}"
    )


# -------------------------------------
# COLOR CODING SEVERITY
# -------------------------------------
def apply_color(cell, vt_text=None, abuse_text=None):

    red = PatternFill(start_color="FFC7CE", fill_type="solid")
    yellow = PatternFill(start_color="FFEB9C", fill_type="solid")
    green = PatternFill(start_color="C6EFCE", fill_type="solid")

    # VT Severity
    if vt_text and "Error" not in vt_text:
        malicious = int(vt_text.split("Malicious:")[1].split()[0])
        suspicious = int(vt_text.split("Suspicious:")[1].split()[0])

        if malicious > 0:
            cell.fill = red
        elif suspicious > 0:
            cell.fill = yellow
        else:
            cell.fill = green

    # AbuseIPDB Severity
    if abuse_text and "Error" not in abuse_text:
        score = int(abuse_text.split("Score:")[1].split()[0])
        if score > 50:
            cell.fill = red
        elif score > 0:
            cell.fill = yellow
        else:
            cell.fill = green


# -------------------------------------
# MULTITHREADING WRAPPER
# -------------------------------------
def parallel_execute(func, items, *args):
    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_map = {executor.submit(func, *args, item): item for item in items}
        for future in as_completed(future_map):
            indicator = future_map[future]
            try:
                result = future.result()
            except Exception as e:
                result = {"error": str(e)}
            results.append((indicator, result))
    return results


# -------------------------------------
# WRITE TO EXCEL (FINAL VERSION WITH STYLING)
# -------------------------------------
def write_to_excel(headers, url_results, ip_results, attachment_results, output="email_report.xlsx"):

    wb = Workbook()

    # -----------------------------
    # SHEET 1 — HEADERS
    # -----------------------------
    ws1 = wb.active
    ws1.title = "Headers"
    ws1.append(["Field", "Value"])

    for k, v in headers.items():
        ws1.append([k, "; ".join(v) if isinstance(v, list) else v])

    # -----------------------------
    # SHEET 2 — REPUTATION
    # -----------------------------
    ws2 = wb.create_sheet("Reputation")
    ws2.append(["Type", "Indicator", "VirusTotal", "AbuseIPDB", "OTX"])

    row = 2

    # URL Results
    for url, vt, otx in url_results:
        vt_text = beautify_vt(vt)
        otx_text = beautify_otx_url(otx)

        ws2.append(["URL", url, vt_text, "N/A", otx_text])
        apply_color(ws2[f"C{row}"], vt_text, None)
        row += 1

    # IP Results
    for ip, vt, abuse, otx in ip_results:
        vt_text = beautify_vt_ip(vt)
        abuse_text = beautify_abuseip(abuse)
        otx_text = beautify_otx_ip(otx)

        ws2.append(["IP", ip, vt_text, abuse_text, otx_text])
        apply_color(ws2[f"C{row}"], vt_text, None)
        apply_color(ws2[f"D{row}"], None, abuse_text)
        row += 1

    # Attachment Results
    for sha, vt, otx in attachment_results:
        vt_text = beautify_vt(vt)
        otx_text = beautify_otx_url(otx)

        ws2.append(["Attachment", sha, vt_text, "N/A", otx_text])
        apply_color(ws2[f"C{row}"], vt_text, None)
        row += 1

    # ---------------------------------
    # APPLY BORDERS + HEADER STYLING
    # ---------------------------------
    thin = Side(style="thin")
    border_style = Border(left=thin, right=thin, top=thin, bottom=thin)

    header_fill = PatternFill(start_color="4B0082", fill_type="solid")  # Dark purple
    header_font = Font(bold=True, color="FFFFFF")  # White text

    for sheet in [ws1, ws2]:

        # Header row styling
        for cell in sheet[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.border = border_style

        # Borders for all data cells
        for row in sheet.iter_rows(min_row=2, max_row=sheet.max_row, max_col=sheet.max_column):
            for cell in row:
                cell.border = border_style

    # ---------------------------------
    # AUTO-FIT COLUMN WIDTHS
    # ---------------------------------
    for sheet in [ws1, ws2]:
        for col in sheet.columns:
            max_len = max(len(str(c.value)) if c.value else 0 for c in col)
            sheet.column_dimensions[col[0].column_letter].width = max_len + 3

    wb.save(output)
    print(f"Excel report generated: {output}")


# -------------------------------------
# MAIN EXECUTION
# -------------------------------------
if __name__ == "__main__":
    api = load_api_keys()

    msg, headers = parse_email_headers("sample.eml")
    urls, attachments = extract_urls_and_attachments(msg)

    # Parallel VT/OTX for URLs
    vt_url_results = parallel_execute(vt_url_lookup, urls, api["VIRUSTOTAL_API_KEY"])
    otx_url_results = parallel_execute(otx_lookup, urls, api["OTX_API_KEY"])

    url_results = []
    for (u, vt), (_, otx) in zip(vt_url_results, otx_url_results):
        url_results.append((u, vt, otx))

    # IP Reputation
    ip_results = []
    if headers["Received"]:
        last = headers["Received"][-1]
        match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", last)
        if match:
            ip = match.group(0)
            vt_ip = vt_ip_lookup(api["VIRUSTOTAL_API_KEY"], ip)
            abuse = abuseipdb_lookup(api["ABUSEIPDB_API_KEY"], ip)
            otx_ip = otx_lookup(api["OTX_API_KEY"], ip)
            ip_results.append((ip, vt_ip, abuse, otx_ip))

    # Parallel VT/OTX for attachments
    hashes = [a["sha256"] for a in attachments]
    vt_att_results = parallel_execute(vt_hash_lookup, hashes, api["VIRUSTOTAL_API_KEY"])
    otx_att_results = parallel_execute(otx_lookup, hashes, api["OTX_API_KEY"])

    attachment_results = []
    for (sha, vt), (_, otx) in zip(vt_att_results, otx_att_results):
        attachment_results.append((sha, vt, otx))

    # Generate Excel
    write_to_excel(headers, url_results, ip_results, attachment_results)
