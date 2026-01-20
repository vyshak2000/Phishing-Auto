import os
import sys
import pandas as pd
from email import policy
from email.parser import Parser
from authheaders import AuthenticationResultsParser

# -----------------------------
# CONFIG
# -----------------------------
RAW_HEADERS_FILE = "raw_headers.txt"
OUTPUT_EXCEL = "headers.xlsx"

# -----------------------------
# READ RAW HEADERS
# -----------------------------
if not os.path.exists(RAW_HEADERS_FILE):
    print(f"[!] {RAW_HEADERS_FILE} not found")
    sys.exit(1)

with open(RAW_HEADERS_FILE, "r", encoding="utf-8", errors="ignore") as f:
    raw_headers = f.read()

# -----------------------------
# PARSE EMAIL HEADERS
# -----------------------------
parser = Parser(policy=policy.default)
msg = parser.parsestr(raw_headers)

# -----------------------------
# BASIC HEADER EXTRACTION
# -----------------------------
results = []

def add_result(category, name, value):
    results.append({
        "Category": category,
        "Header": name,
        "Value": value
    })

basic_headers = [
    "From", "To", "Subject", "Date",
    "Message-ID", "Return-Path",
    "Reply-To", "MIME-Version"
]

for h in basic_headers:
    add_result("Basic", h, msg.get(h, "Not Found"))

# -----------------------------
# RECEIVED HEADERS (MAIL PATH)
# -----------------------------
received_headers = msg.get_all("Received", [])

if received_headers:
    for idx, rec in enumerate(received_headers, start=1):
        add_result("Mail Path", f"Received #{idx}", rec)
else:
    add_result("Mail Path", "Received", "Not Found")

# -----------------------------
# AUTHENTICATION RESULTS
# -----------------------------
auth_results_raw = msg.get_all("Authentication-Results", [])

if auth_results_raw:
    for ar in auth_results_raw:
        try:
            parsed = AuthenticationResultsParser.parse(ar)

            for method, result in parsed.results.items():
                value = f"{result.result}"
                if result.comment:
                    value += f" ({result.comment})"
                add_result("Authentication", method.upper(), value)

        except Exception as e:
            add_result("Authentication", "Authentication-Results", ar)
else:
    add_result("Authentication", "Authentication-Results", "Not Found")

# -----------------------------
# SPF / DKIM / DMARC SUMMARY
# -----------------------------
def extract_auth_summary(auth_type):
    for r in results:
        if r["Header"].lower() == auth_type.lower():
            return r["Value"]
    return "Not Found"

add_result("Summary", "SPF", extract_auth_summary("spf"))
add_result("Summary", "DKIM", extract_auth_summary("dkim"))
add_result("Summary", "DMARC", extract_auth_summary("dmarc"))

# -----------------------------
# CREATE EXCEL
# -----------------------------
df = pd.DataFrame(results)

with pd.ExcelWriter(OUTPUT_EXCEL, engine="openpyxl") as writer:
    df.to_excel(writer, index=False, sheet_name="Header Analysis")

print(f"[+] Analysis written to {OUTPUT_EXCEL}")

# -----------------------------
# AUTO OPEN EXCEL FILE
# -----------------------------
try:
    if sys.platform.startswith("win"):
        os.startfile(OUTPUT_EXCEL)
    elif sys.platform.startswith("darwin"):
        os.system(f"open {OUTPUT_EXCEL}")
    else:
        os.system(f"xdg-open {OUTPUT_EXCEL}")
except Exception as e:
    print(f"[!] Could not auto-open file: {e}")
